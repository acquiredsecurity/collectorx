// Package web provides the embedded static files for the web UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFS embed.FS

// StaticFiles returns the embedded static file system, rooted at the static/ directory.
func StaticFiles() fs.FS {
	sub, _ := fs.Sub(staticFS, "static")
	return sub
}
