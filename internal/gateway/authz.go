package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

// Forward-auth endpoints, one per proxy. The proxy sends the client's headers here instead of the
// request itself; LimitPlane answers 200 to let it through or the response to send instead.
// Each dialect reads only the headers its own proxy writes, so a client can't name a cheaper
// route by sending another proxy's header (X-Original-URI through Traefik, say).
const (
	AuthzEnvoy   = "/authz/envoy" // ext_authz path_prefix: Envoy appends the original path
	AuthzNginx   = "/authz/nginx" // auth_request: X-Original-URI, X-Original-Method
	AuthzTraefik = "/authz/traefik"
)

type proxy uint8

const (
	envoy proxy = iota
	nginx
	traefik
)

// Authz serves the three forward-auth endpoints. It decides with the same Check as Middleware,
// so bans, degraded mode, fail-closed, the audit ring and SSE behave the same.
//
// It routes by hand: a ServeMux would answer a non-canonical original path such as //v1 with a
// redirect, which the proxy would pass to the client instead of a decision.
func (g *Gateway) Authz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case strings.HasPrefix(p, AuthzEnvoy+"/"):
			g.authz(w, r, envoy)
		case p == AuthzNginx:
			g.authz(w, r, nginx)
		case p == AuthzTraefik:
			g.authz(w, r, traefik)
		default:
			http.NotFound(w, r)
		}
	})
}

func (g *Gateway) authz(w http.ResponseWriter, r *http.Request, p proxy) {
	method, path, ok := original(r, p)
	if !ok { // the proxy isn't sending what its dialect needs: fail loudly, never price "/"
		http.Error(w, "limitplane: check request has no original URI for this proxy", http.StatusBadRequest)
		return
	}
	d, reset := g.Check(r, method, path)
	h := w.Header()
	// For the app behind: the proxy copies these over anything the client sent.
	h["X-Limitplane-Tenant"], h["X-Limitplane-Tier"] = []string{d.Tenant}, []string{d.Tier}
	writeHeaders(h, d, reset)
	if d.Allowed {
		w.WriteHeader(http.StatusOK)
		return
	}
	h["X-Limitplane-Reason"] = []string{d.Reason}
	code := status(d)
	if p == nginx && code == http.StatusTooManyRequests {
		code = http.StatusForbidden // auth_request turns anything but 2xx, 401 and 403 into a 500
	}
	deny(w, d, code)
}

// original recovers the method and path of the request the proxy is asking about. The query never
// takes part in pricing; escapes are decoded and the path cleaned, so /v1/%67enerate, /v1//generate
// and /./v1/generate cost what /v1/generate does, as the app behind will route them.
func original(r *http.Request, p proxy) (method, path string, ok bool) {
	var uri string
	switch p {
	case envoy: // the check request is the original method on prefix + path; Go already split and decoded it
		return r.Method, clean(strings.TrimPrefix(r.URL.Path, AuthzEnvoy)), true
	case nginx:
		uri, method = r.Header.Get("X-Original-Uri"), r.Header.Get("X-Original-Method")
	case traefik:
		uri, method = r.Header.Get("X-Forwarded-Uri"), r.Header.Get("X-Forwarded-Method")
	}
	if method == "" {
		method = r.Method
	}
	uri, _, _ = strings.Cut(uri, "?")
	if !strings.HasPrefix(uri, "/") {
		return "", "", false
	}
	path, err := url.PathUnescape(uri)
	return method, clean(path), err == nil
}
