package webapi

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// webClientAssets contains the static browser client served from /client/.
//
//go:embed webclient/*
var webClientAssets embed.FS

func webClientFiles() fs.FS {
	clientFiles, err := fs.Sub(webClientAssets, "webclient")
	if err != nil {
		panic(err)
	}
	return clientFiles
}

func webClientHandler() http.Handler {
	clientFiles := webClientFiles()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assetPath := strings.TrimPrefix(r.URL.Path, "/client/")
		assetPath = path.Clean("/" + assetPath)
		assetPath = strings.TrimPrefix(assetPath, "/")

		// Older deployments and bookmarks used /client/app/. Serve the same
		// embedded client there instead of letting a directory listing or another
		// static app leak through.
		if assetPath == "." || assetPath == "" || assetPath == "app" || assetPath == "app/" {
			serveWebClientAsset(w, r, clientFiles, "index.html")
			return
		}
		if strings.HasPrefix(assetPath, "app/") {
			assetPath = strings.TrimPrefix(assetPath, "app/")
		}

		if assetPath == "" || strings.HasSuffix(assetPath, "/") {
			http.NotFound(w, r)
			return
		}

		serveWebClientAsset(w, r, clientFiles, assetPath)
	})
}

func serveWebClientAsset(w http.ResponseWriter, r *http.Request, clientFiles fs.FS, assetPath string) {
	data, err := fs.ReadFile(clientFiles, assetPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	stat, err := fs.Stat(clientFiles, assetPath)
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}

	http.ServeContent(w, r, assetPath, stat.ModTime(), bytes.NewReader(data))
}
