package webapi

import (
	"embed"
	"io/fs"
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
