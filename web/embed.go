// Package web holds the embedded dashboard.
package web

import "embed"

//go:embed index.html app.css app.js globe.js logo.svg
var FS embed.FS
