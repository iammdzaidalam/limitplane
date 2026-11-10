package kube

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPath(t *testing.T) {
	c := &Client{Namespace: "prod"}
	for _, x := range []struct {
		r    Resource
		name string
		want string
	}{
		{Secrets, "", "/api/v1/namespaces/prod/secrets"},
		{Secrets, "k", "/api/v1/namespaces/prod/secrets/k"},
		{Policies, "", "/apis/limitplane.dev/v1alpha1/namespaces/prod/ratelimitpolicies"},
		{Tenants, "acme", "/apis/limitplane.dev/v1alpha1/namespaces/prod/tenants/acme"},
		{Leases, "l", "/apis/coordination.k8s.io/v1/namespaces/prod/leases/l"},
		{Events, "", "/api/v1/namespaces/prod/events"},
	} {
		if got := c.Path(x.r, x.name); got != x.want {
			t.Errorf("Path(%v, %q) = %s", x.r, x.name, got)
		}
	}
}

// One request as the API server sees it.
type seen struct {
	method, path, auth, accept, ctype, body string
}

func recorder(t *testing.T, code int, reply string) (*Client, <-chan seen) {
	ch := make(chan seen, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- seen{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Accept"), r.Header.Get("Content-Type"), string(b)}
		w.WriteHeader(code)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, Namespace: "ns", HTTP: srv.Client()}, ch
}

func TestRequestShape(t *testing.T) {
	c, reqs := recorder(t, 200, `{}`)
	ctx := context.Background()
	if err := c.Get(ctx, "/x", &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; r.auth != "" || r.accept != "application/json" || r.ctype != "" || r.method != "GET" {
		t.Fatalf("anonymous GET %+v", r)
	}
	tok := "t1"
	c.Token = func() string { return tok }
	c.PatchStatus(ctx, "/apis/x/tenants/acme", map[string]int{"monthlyUsed": 3})
	r := <-reqs
	if r.auth != "Bearer t1" || r.method != "PATCH" || r.path != "/apis/x/tenants/acme/status" ||
		r.ctype != "application/merge-patch+json" || r.body != `{"status":{"monthlyUsed":3}}` {
		t.Fatalf("PatchStatus %+v", r)
	}
	tok = "t2" // rotated in place by the kubelet: the next request uses it
	c.Update(ctx, "/y", map[string]string{"a": "b"}, nil)
	if r := <-reqs; r.auth != "Bearer t2" || r.method != "PUT" || r.ctype != "application/json" {
		t.Fatalf("Update %+v", r)
	}
	tok = ""
	c.Create(ctx, "/z", map[string]string{}, nil)
	if r := <-reqs; r.auth != "" || r.method != "POST" {
		t.Fatalf("Create with an empty token %+v", r)
	}
}

func TestAPIErrors(t *testing.T) {
	for _, x := range []struct {
		code int
		body string
		msg  string
	}{
		{404, `{"kind":"Status","message":"tenants \"x\" not found"}`, `tenants "x" not found`},
		{409, `{"message":"the object has been modified"}`, "the object has been modified"},
		{403, `not json`, ""},
		{500, ``, ""},
	} {
		c, _ := recorder(t, x.code, x.body)
		err := c.Get(context.Background(), "/x", nil)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != x.code || ae.Message != x.msg || !IsStatus(err, x.code) || IsStatus(err, x.code+1) {
			t.Errorf("%d: %#v", x.code, err)
		}
	}
	if IsStatus(errors.New("dial tcp: refused"), 404) || IsStatus(nil, 404) {
		t.Fatal("only APIErrors have a status")
	}
	c, _ := recorder(t, 200, `{"broken`)
	var v map[string]any
	if err := c.Get(context.Background(), "/x", &v); err == nil {
		t.Fatal("bad JSON body must error")
	}
}

func TestEventShape(t *testing.T) {
	c, reqs := recorder(t, 201, `{}`)
	ref := Ref{APIVersion: apiVersion, Kind: "Tenant", Name: "acme", Namespace: "ns", UID: "u1"}
	if err := c.Event(context.Background(), ref, "Warning", "QuotaAlert", "used 80%"); err != nil {
		t.Fatal(err)
	}
	r := <-reqs
	var ev struct {
		Metadata       ObjectMeta
		InvolvedObject Ref
		Type, Reason   string
		Message        string
		Source         map[string]string
		FirstTimestamp string
		Count          int
	}
	if err := json.Unmarshal([]byte(r.body), &ev); err != nil {
		t.Fatal(err)
	}
	if r.path != "/api/v1/namespaces/ns/events" || ev.Metadata.GenerateName != "acme-" || ev.InvolvedObject != ref ||
		ev.Type != "Warning" || ev.Reason != "QuotaAlert" || ev.Source["component"] != "limitplane" || ev.Count != 1 {
		t.Fatalf("event %+v at %s", ev, r.path)
	}
	if _, err := time.Parse(time.RFC3339, ev.FirstTimestamp); err != nil {
		t.Fatalf("firstTimestamp %q", ev.FirstTimestamp)
	}
}

// Leases use MicroTime: exactly six fractional digits, which the API server insists on.
func TestMicroTime(t *testing.T) {
	at := time.Date(2026, 11, 10, 9, 8, 7, 123456789, time.FixedZone("x", 3600))
	b, err := json.Marshal(MicroTime{at})
	if err != nil || string(b) != `"2026-11-10T08:08:07.123456Z"` {
		t.Fatalf("%s %v", b, err)
	}
	var back MicroTime
	if err := json.Unmarshal(b, &back); err != nil || !back.Equal(at.Truncate(time.Microsecond)) {
		t.Fatalf("round trip %v %v", back, err)
	}
	b, _ = json.Marshal(LeaseSpec{HolderIdentity: "a"})
	if strings.Contains(string(b), "Time") {
		t.Fatalf("zero times must be omitted: %s", b)
	}
	for in, ok := range map[string]bool{`""`: true, `null`: true, `"2026-11-10T08:08:07Z"`: true, `"yesterday"`: false, `5`: false} {
		var m MicroTime
		if err := json.Unmarshal([]byte(in), &m); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestInClusterOutsideACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InCluster(); err == nil || !strings.Contains(err.Error(), "not running in a cluster") {
		t.Fatalf("got %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if _, err := InCluster(); err == nil { // no service account files on a dev machine
		t.Fatal("want missing ca.crt error")
	}
}
