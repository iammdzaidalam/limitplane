// Package kube runs LimitPlane as a Kubernetes operator: a small REST client, list/watch caches,
// Lease leader election and the reconcilers that turn CRDs into the live policy.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Resource names one namespaced API collection. Group "" is the core API.
type Resource struct{ Group, Version, Plural string }

var (
	Policies = Resource{"limitplane.dev", "v1alpha1", "ratelimitpolicies"}
	Tenants  = Resource{"limitplane.dev", "v1alpha1", "tenants"}
	Secrets  = Resource{"", "v1", "secrets"}
	Events   = Resource{"", "v1", "events"}
	Leases   = Resource{"coordination.k8s.io", "v1", "leases"}
)

// Client talks to one namespace of the API server with plain net/http and encoding/json.
type Client struct {
	Base      string // e.g. https://10.96.0.1:443
	Namespace string
	HTTP      *http.Client
	Token     func() string
}

// InCluster builds a client from the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kube: KUBERNETES_SERVICE_HOST/PORT unset, not running in a cluster")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	ns, err := os.ReadFile(saDir + "/namespace")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kube: no certificates in ca.crt")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &Client{
		Base:      "https://" + net.JoinHostPort(host, port),
		Namespace: strings.TrimSpace(string(ns)),
		HTTP:      &http.Client{Transport: tr}, // no Timeout: watches are long-lived, contexts bound each call
		// Re-read per request: the kubelet rotates projected tokens in place.
		Token: func() string {
			b, _ := os.ReadFile(saDir + "/token")
			return strings.TrimSpace(string(b))
		},
	}, nil
}

// Path is the URL path of a collection (name "") or one object in the client's namespace.
func (c *Client) Path(r Resource, name string) string {
	p := "/apis/" + r.Group + "/" + r.Version
	if r.Group == "" {
		p = "/api/" + r.Version
	}
	p += "/namespaces/" + c.Namespace + "/" + r.Plural
	if name != "" {
		p += "/" + name
	}
	return p
}

// APIError is a non-2xx answer from the API server.
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("kube: %d %s", e.Code, e.Message) }

// IsStatus reports whether err is an APIError with this HTTP code.
func IsStatus(err error, code int) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}

// request sends body as JSON and returns the open response, or an APIError for non-2xx codes.
func (c *Client) request(ctx context.Context, method, path, contentType string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != nil {
		if t := c.Token(); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		defer res.Body.Close()
		var st struct{ Message string }
		json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&st)
		return nil, &APIError{Code: res.StatusCode, Message: st.Message}
	}
	return res, nil
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := c.request(ctx, method, path, contentType, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		_, err = io.Copy(io.Discard, res.Body)
		return err
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, "", nil, out)
}

func (c *Client) Create(ctx context.Context, path string, obj, out any) error {
	return c.do(ctx, http.MethodPost, path, "application/json", obj, out)
}

// Update replaces an object. The API server rejects it with 409 if obj's resourceVersion is stale.
func (c *Client) Update(ctx context.Context, path string, obj, out any) error {
	return c.do(ctx, http.MethodPut, path, "application/json", obj, out)
}

// PatchStatus merge-patches the status subresource, so no resourceVersion round trip is needed.
func (c *Client) PatchStatus(ctx context.Context, path string, status any) error {
	return c.do(ctx, http.MethodPatch, path+"/status", "application/merge-patch+json", map[string]any{"status": status}, nil)
}

// Ref points an Event at the object it is about.
type Ref struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	UID        string `json:"uid,omitempty"`
}

// Event records a core/v1 Event, which kubectl describe shows under the object.
func (c *Client) Event(ctx context.Context, about Ref, typ, reason, msg string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	ev := map[string]any{
		"metadata":       ObjectMeta{GenerateName: about.Name + "-", Namespace: c.Namespace},
		"involvedObject": about,
		"type":           typ,
		"reason":         reason,
		"message":        msg,
		"source":         map[string]string{"component": "limitplane"},
		"firstTimestamp": now,
		"lastTimestamp":  now,
		"count":          1,
	}
	return c.Create(ctx, c.Path(Events, ""), ev, nil)
}
