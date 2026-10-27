package server

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

// demo is a stand-in upstream: a cheap health route and an expensive fake LLM route.
func demo() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		d, _ := gateway.DecisionFrom(r.Context())
		writeJSON(w, 200, map[string]any{"pong": true, "tenant": d.Tenant, "remaining": d.Remaining})
	})
	m.HandleFunc("POST /v1/generate", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Prompt string }
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in)
		select {
		case <-time.After(time.Duration(40+rand.IntN(80)) * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		d, _ := gateway.DecisionFrom(r.Context())
		writeJSON(w, 200, map[string]any{
			"text":   fmt.Sprintf("echo: %.200s", in.Prompt),
			"tenant": d.Tenant, "cost": d.Cost, "remaining": d.Remaining,
		})
	})
	return m
}
