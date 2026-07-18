package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/wire"
)

// blankIconGIF stands in for the blank placeholder the real BART service returns
// for the clear-icon hash; distinct from iconGIF so tests can tell them apart.
var blankIconGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xff}

// newExpressionsHandler builds a handler whose target user has the given icon,
// or no icon when id is nil. Its BART mock mirrors the real service: the
// clear-icon hash resolves to the blank placeholder, any other hash to iconGIF.
func newExpressionsHandler(id *wire.BARTID) *ExpressionsHandler {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).Return(id, nil).Maybe()

	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x10_0x04_BARTDownloadQuery) bool { return q.HasClearIconHash() })).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: blankIconGIF}}, nil).Maybe()
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF}}, nil).Maybe()

	return NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, slog.Default())
}

func TestExpressionsHandler_Get_ServesIconBytes(t *testing.T) {
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, iconGIF, w.Body.Bytes())
	assert.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	// The URL pins the icon hash, so it always resolves to the same image.
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_IconWithoutHashIsNotCached(t *testing.T) {
	// Without a hash the URL keeps resolving to whatever the current icon is, so
	// caching it would pin a stale image.
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_MissingIconServesPlaceholder(t *testing.T) {
	// A user with no icon still serves the blank placeholder for the hash-less
	// URL, so the client's <img> renders something and a cleared icon stops
	// showing the previous one rather than 404ing.
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, blankIconGIF, w.Body.Bytes())
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_BartIdServesRequestedHash(t *testing.T) {
	// Even though the user's *current* icon is hash B, a URL pinned to hash A must
	// serve A's bytes and cache immutably — otherwise a cached URL could later
	// resolve to a different image.
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	bytesA := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xa1}
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x10_0x04_BARTDownloadQuery) bool {
			return bytes.Equal(q.Hash, []byte{0xaa})
		})).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: bytesA}}, nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, slog.Default())

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=aa", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, bytesA, w.Body.Bytes())
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
	bartService.AssertExpectations(t)
}

func TestExpressionsHandler_Get_UnknownBartIdNotFound(t *testing.T) {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	// An empty reply means the hash is not stored.
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{}}, nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, slog.Default())

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=abcdef", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestExpressionsHandler_Get_ListsBigBuddyIcon(t *testing.T) {
	// This is the shape the client scans for its large icon rendering.
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly", nil)
	r.Host = "api.example.com"
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var got struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				Expressions []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"expressions"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	assert.Equal(t, 200, got.Response.StatusCode)
	assert.Len(t, got.Response.Data.Expressions, 1)
	assert.Equal(t, "bigBuddyIcon", got.Response.Data.Expressions[0].Type)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
		got.Response.Data.Expressions[0].URL)
}

func TestExpressionsHandler_Get_ListsNothingWithoutIcon(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"expressions":[]`)
}

func TestExpressionsHandler_Get_Redirect(t *testing.T) {
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&f=redirect", nil)
	r.Host = "api.example.com"
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
		w.Header().Get("Location"))
}

func TestExpressionsHandler_Get_RedirectWithoutIcon(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&f=redirect", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestExpressionsHandler_Get_MissingTarget(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
