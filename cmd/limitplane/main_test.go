package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDefaultConfigParses(t *testing.T) {
	if _, err := loadConfig(""); err != nil {
		t.Fatal(err)
	}
}

func TestProxyForwardedFor(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Forwarded-For")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	for _, tc := range []struct {
		trust bool
		want  string
	}{
		{false, "127.0.0.1"},         // spoofed header dropped
		{true, "6.6.6.6, 127.0.0.1"}, // trusted chain appended to
	} {
		ts := httptest.NewServer(proxy(u, tc.trust))
		req, _ := http.NewRequest("GET", ts.URL+"/x", nil)
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if xff := <-got; xff != tc.want {
			t.Errorf("trust=%v: XFF %q, want %q", tc.trust, xff, tc.want)
		}
	}
}
