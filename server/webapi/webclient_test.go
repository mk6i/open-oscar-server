package webapi

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
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

func TestWebClientHandlerServesLegacyAppPath(t *testing.T) {
	handler := webClientHandler()

	req := httptest.NewRequest(http.MethodGet, "/client/app/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "ICQ Web")
	assert.NotContains(t, rr.Body.String(), "__pycache__")
}

func TestWebClientHandlerServesAssetsUnderLegacyAppPath(t *testing.T) {
	handler := webClientHandler()

	req := httptest.NewRequest(http.MethodGet, "/client/app/app.js", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "/auth/clientLogin")
}
