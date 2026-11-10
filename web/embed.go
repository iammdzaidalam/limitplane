// Package web holds the embedded dashboard.
package web

import "embed"

//go:embed index.html app.css app.js ai.js globe.js logo.svg
var FS embed.FS
