package webapi

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebClientFiles(t *testing.T) {
	clientFiles := webClientFiles()

	tests := []struct {
		name string
		path string
	}{
		{name: "index page", path: "index.html"},
		{name: "stylesheet", path: "styles.css"},
		{name: "script", path: "app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := fs.ReadFile(clientFiles, tt.path)
			require.NoError(t, err)
			assert.NotEmpty(t, data)
		})
	}
}

func TestWebClientAppIncludesCoreChatFeatures(t *testing.T) {
	clientFiles := webClientFiles()

	data, err := fs.ReadFile(clientFiles, "app.js")
	require.NoError(t, err)
	app := string(data)

	assert.Contains(t, app, "/client/config")
	assert.Contains(t, app, "/auth/clientLogin")
	assert.Contains(t, app, "/presence/get")
	assert.Contains(t, app, "/presence/setState")
	assert.Contains(t, app, "/im/sendIM")
	assert.Contains(t, app, "localStorage")
}
