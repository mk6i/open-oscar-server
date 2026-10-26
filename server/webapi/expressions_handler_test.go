package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// blankIconGIF stands in for the blank placeholder the real BART service returns
// for the clear-icon hash; distinct from iconGIF so tests can tell them apart.
var blankIconGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xff}

// newExpressionsHandler builds a handler whose target user has the given icon,
// or no icon when id is nil. Its BART mock mirrors the real service: the
// clear-icon hash resolves to the blank placeholder, any other hash to iconGIF.
func newExpressionsHandler(t *testing.T, id *wire.BARTID) *ExpressionsHandler {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).Return(id, nil).Maybe()

	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x10_0x04_BARTDownloadQuery) bool { return q.HasClearIconHash() })).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: blankIconGIF}}, nil).Maybe()
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF}}, nil).Maybe()

	return NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, slog.Default())
}

func TestExpressionsHandler_Get_ServesIconBytes(t *testing.T) {
	h := newExpressionsHandler(t, bartID([]byte{0xde, 0xad}))

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
	h := newExpressionsHandler(t, bartID([]byte{0xde, 0xad}))

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
	h := newExpressionsHandler(t, nil)

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
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	bytesA := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xa1}
	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything,
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
}

func TestExpressionsHandler_Get_UnknownBartIdNotFound(t *testing.T) {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	// An empty reply means the hash is not stored.
	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything, mock.Anything).
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
	h := newExpressionsHandler(t, bartID([]byte{0xde, 0xad}))

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
	h := newExpressionsHandler(t, nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"expressions":[]`)
}

func TestExpressionsHandler_Get_Redirect(t *testing.T) {
	h := newExpressionsHandler(t, bartID([]byte{0xde, 0xad}))

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
	h := newExpressionsHandler(t, nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&f=redirect", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestExpressionsHandler_Get_MissingTarget(t *testing.T) {
	h := newExpressionsHandler(t, nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// newUploadSession returns a running session whose OSCAR server answers BART
// uploads with upload and holds the feedbag that server holds.
func newUploadSession(t *testing.T, upload wire.SNAC_0x10_0x03_BARTUploadReply, server *feedbagServer) (*Session, *fakeConn) {
	conn := newFakeConn().answering(firstAnswer(bartUploads(upload), server.respond))
	sess := newTestSession(t, conn)
	loadTestFeedbag(t, sess)
	return sess, conn
}

// bartUploads returns a responder that answers BART uploads with reply.
func bartUploads(reply wire.SNAC_0x10_0x03_BARTUploadReply) func(req wire.SNACMessage) []wire.SNACMessage {
	return func(req wire.SNACMessage) []wire.SNACMessage {
		if _, ok := req.Body.(wire.SNAC_0x10_0x02_BARTUploadQuery); !ok {
			return nil
		}
		return []wire.SNACMessage{{
			Frame: wire.SNACFrame{FoodGroup: wire.BART, SubGroup: wire.BARTUploadReply},
			Body:  reply,
		}}
	}
}

// The Android client posts the raw JPEG with a Content-Type of
// application/x-www-form-urlencoded. The handler must read the body as bytes and
// must not let anything parse it as a form.
func TestExpressionsHandler_Upload_StoresAndPublishesIcon(t *testing.T) {
	image := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	hash := []byte{0xde, 0xad, 0xbe, 0xef}

	// The root group lives at GroupID 0 / ItemID 0.
	server := newFeedbagServer(wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup})
	session, conn := newUploadSession(t, wire.SNAC_0x10_0x03_BARTUploadReply{
		Code: wire.BARTReplyCodesSuccess,
		ID: wire.BARTID{
			Type:     wire.BARTTypesBuddyIcon,
			BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash},
		},
	}, server)

	h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, slog.Default())

	req := httptest.NewRequest(http.MethodPost,
		"/expressions/upload?f=json&aimsid=sid&type=buddyIcon", bytes.NewReader(image))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Upload(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []any{wire.SNAC_0x10_0x02_BARTUploadQuery{Type: wire.BARTTypesBuddyIcon, Data: image}},
		conn.sentOf(wire.BART, wire.BARTUploadQuery))

	var got struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, 200, got.Response.StatusCode)
	// type as 4 hex digits, then the content hash.
	assert.Equal(t, "0001deadbeef", got.Response.Data.ID)

	// The icon must be published to the feedbag, or expressions/get never sees it.
	changes := sentFeedbagChanges(conn)
	require.Len(t, changes, 1)
	assert.Equal(t, uint16(wire.FeedbagInsertItem), changes[0].SubGroup)
	upserted := changes[0].Items
	require.Len(t, upserted, 1)
	assert.Equal(t, wire.FeedbagClassIdBart, upserted[0].ClassID)
	assert.Equal(t, "1", upserted[0].Name)
	// A first icon must not land on the root group's (0, 0) row.
	assert.NotZero(t, upserted[0].ItemID)
	b, ok := upserted[0].Bytes(wire.FeedbagAttributesBartInfo)
	assert.True(t, ok)
	info := wire.BARTInfo{}
	assert.NoError(t, wire.UnmarshalBE(&info, bytes.NewBuffer(b)))
	assert.Equal(t, hash, info.Hash)

	// The session's feedbag holds what the server confirmed.
	assert.Equal(t, server.stored(), session.Feedbag())
}

// An existing icon is replaced in place rather than added alongside.
func TestExpressionsHandler_Upload_ReusesExistingFeedbagItem(t *testing.T) {
	server := newFeedbagServer(wire.FeedbagItem{GroupID: 7, ItemID: 9, ClassID: wire.FeedbagClassIdBart, Name: "1"})
	session, conn := newUploadSession(t, wire.SNAC_0x10_0x03_BARTUploadReply{
		Code: wire.BARTReplyCodesSuccess,
		ID:   wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: []byte{0x01}}},
	}, server)

	h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, slog.Default())
	req := httptest.NewRequest(http.MethodPost,
		"/expressions/upload?type=buddyIcon", bytes.NewReader([]byte{0x01, 0x02}))
	rr := httptest.NewRecorder()

	h.Upload(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	changes := sentFeedbagChanges(conn)
	require.Len(t, changes, 1)
	require.Len(t, changes[0].Items, 1)
	assert.Equal(t, uint16(7), changes[0].Items[0].GroupID)
	assert.Equal(t, uint16(9), changes[0].Items[0].ItemID)
	// Other instances are relayed this frame verbatim, so replacing an icon has
	// to go out as an update of an item they already hold, not an insert.
	assert.Equal(t, uint16(wire.FeedbagUpdateItem), changes[0].SubGroup)
}

func TestExpressionsHandler_Upload_ReportsUnpublishedIcon(t *testing.T) {
	server := newFeedbagServer()
	server.status = func(wire.SNACMessage) []wire.SNACMessage {
		return []wire.SNACMessage{snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost)}
	}
	session, _ := newUploadSession(t, wire.SNAC_0x10_0x03_BARTUploadReply{
		Code: wire.BARTReplyCodesSuccess,
		ID:   wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: []byte{0x01}}},
	}, server)

	h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, slog.Default())
	req := httptest.NewRequest(http.MethodPost,
		"/expressions/upload?type=buddyIcon", bytes.NewReader([]byte{0x01, 0x02}))
	rr := httptest.NewRecorder()

	h.Upload(rr, req, session)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "failed to publish expression")
	assert.Empty(t, session.Feedbag(), "the rejected change is discarded")
}

func TestExpressionsHandler_Upload_RejectsBadRequests(t *testing.T) {
	cases := []struct {
		name string
		url  string
		body []byte
	}{
		{"missing type", "/expressions/upload?f=json", []byte{0x01}},
		{"unsupported type", "/expressions/upload?type=wallpaper", []byte{0x01}},
		{"empty body", "/expressions/upload?type=buddyIcon", nil},
		{"oversized body", "/expressions/upload?type=buddyIcon", make([]byte, bartUploadMaxBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newFakeConn()
			h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, slog.Default())

			req := httptest.NewRequest(http.MethodPost, tc.url, bytes.NewReader(tc.body))
			rr := httptest.NewRecorder()
			h.Upload(rr, req, newTestSession(t, conn))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			// Nothing may be stored or published when the request is rejected.
			assert.Empty(t, conn.sentSNACs())
		})
	}
}

// iconGIF stands in for buddy icon image bytes.
var iconGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00}

func bartID(hash []byte) *wire.BARTID {
	return &wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash},
	}
}

func TestBuddyIconSource_URL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		id      *wire.BARTID
		idErr   error
		want    string
	}{
		{
			name:    "user with an icon gets a URL carrying the icon hash",
			baseURL: "http://api.example.com",
			id:      bartID([]byte{0xde, 0xad, 0xbe, 0xef}),
			want:    "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=deadbeef",
		},
		{
			name:    "user without an icon gets no URL",
			baseURL: "http://api.example.com",
			id:      nil,
			want:    "",
		},
		{
			name:    "a cleared icon is not published",
			baseURL: "http://api.example.com",
			id:      bartID(wire.GetClearIconHash()),
			want:    "",
		},
		{
			name:    "a lookup failure is not fatal, it just yields no icon",
			baseURL: "http://api.example.com",
			idErr:   errors.New("db exploded"),
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iconRetriever := newMockBuddyIconRetriever(t)
			iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("mikekelly")).
				Return(tt.id, tt.idErr).Once()

			s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
			got := s.URL(context.Background(), tt.baseURL, state.NewIdentScreenName("mikekelly"))

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuddyIconSource_URL_NoBaseURLSkipsLookup(t *testing.T) {
	// Callers with no origin to build an absolute URL against opt out by passing
	// an empty baseURL. That must not cost a lookup.
	iconRetriever := newMockBuddyIconRetriever(t)

	s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
	got := s.URL(context.Background(), "", state.NewIdentScreenName("mikekelly"))

	assert.Empty(t, got)
	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, mock.Anything)
}

func TestBuddyIconSource_URL_UsesNormalizedScreenName(t *testing.T) {
	// The URL targets the normalized screen name, which is what the endpoint
	// resolves against and what the client keys users by.
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).
		Return(bartID([]byte{0x01}), nil).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
	got := s.URL(context.Background(), "http://api.example.com", state.NewIdentScreenName("Mike Kelly"))

	assert.Equal(t, "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=01", got)
}

func TestBuddyIconSource_Image(t *testing.T) {
	hash := []byte{0xde, 0xad}

	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("mikekelly")).
		Return(bartID(hash), nil).Once()

	// Image resolves the current hash from metadata, then downloads that exact
	// hash. The download query is keyed by hash; flags are irrelevant to the
	// lookup, so it carries only the type and hash.
	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, wire.SNACFrame{}, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: "mikekelly",
		BARTID:     wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: hash}},
	}).Return(wire.SNACMessage{
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF},
	}, nil).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, BARTService: bartService, Logger: slog.Default()}
	got, err := s.Image(context.Background(), state.NewIdentScreenName("mikekelly"))

	assert.NoError(t, err)
	assert.Equal(t, iconGIF, got)
}

func TestBuddyIconSource_ImageForHash(t *testing.T) {
	hash := []byte{0xca, 0xfe}

	// ImageForHash downloads the requested hash directly, without consulting the
	// user's current icon metadata.
	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, wire.SNACFrame{}, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: "mikekelly",
		BARTID:     wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: hash}},
	}).Return(wire.SNACMessage{
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF},
	}, nil).Once()

	s := BuddyIconSource{BARTService: bartService, Logger: slog.Default()}
	got, err := s.ImageForHash(context.Background(), state.NewIdentScreenName("mikekelly"), hash)

	assert.NoError(t, err)
	assert.Equal(t, iconGIF, got)
}

func TestBuddyIconSource_ImageForHash_NotFound(t *testing.T) {
	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{}}, nil).Once()

	s := BuddyIconSource{BARTService: bartService, Logger: slog.Default()}
	_, err := s.ImageForHash(context.Background(), state.NewIdentScreenName("mikekelly"), []byte{0x01})

	assert.ErrorIs(t, err, ErrNoBuddyIcon)
}

func TestBuddyIconSource_PublishedURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		id      *wire.BARTID
		idErr   error
		want    string
	}{
		{
			name:    "an icon yields a content-addressed URL",
			baseURL: "http://api.example.com",
			id:      bartID([]byte{0xde, 0xad, 0xbe, 0xef}),
			want:    "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=deadbeef",
		},
		{
			name:    "no icon still yields a hash-less placeholder URL",
			baseURL: "http://api.example.com",
			id:      nil,
			want:    "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon",
		},
		{
			name:    "a cleared icon yields the placeholder URL",
			baseURL: "http://api.example.com",
			id:      bartID(wire.GetClearIconHash()),
			want:    "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon",
		},
		{
			name:    "a lookup failure yields no URL",
			baseURL: "http://api.example.com",
			idErr:   errors.New("db exploded"),
			want:    "",
		},
		{
			name:    "no base URL yields no URL",
			baseURL: "",
			id:      bartID([]byte{0x01}),
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iconRetriever := newMockBuddyIconRetriever(t)
			iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("mikekelly")).
				Return(tt.id, tt.idErr).Maybe()

			s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
			got := s.PublishedURL(context.Background(), tt.baseURL, state.NewIdentScreenName("mikekelly"))

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuddyIconSource_Image_NoIcon(t *testing.T) {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).Return(nil, nil).Once()

	bartService := newMockBARTService(t)

	s := BuddyIconSource{IconRetriever: iconRetriever, BARTService: bartService, Logger: slog.Default()}
	_, err := s.Image(context.Background(), state.NewIdentScreenName("mikekelly"))

	assert.ErrorIs(t, err, ErrNoBuddyIcon)
	// No icon means there is nothing to ask BART for.
	bartService.AssertNotCalled(t, "RetrieveItem", mock.Anything, mock.Anything, mock.Anything)
}

func TestBuddyIconSource_URLForHash(t *testing.T) {
	// URLForHash never touches the retriever: the hash is supplied by the caller.
	s := BuddyIconSource{Logger: slog.Default()}
	sn := state.NewIdentScreenName("Mike Kelly")

	t.Run("hash yields the content-addressed URL", func(t *testing.T) {
		assert.Equal(t,
			"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=deadbeef",
			s.URLForHash("http://api.example.com", sn, []byte{0xde, 0xad, 0xbe, 0xef}))
	})

	t.Run("no hash yields the placeholder URL", func(t *testing.T) {
		assert.Equal(t,
			"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon",
			s.URLForHash("http://api.example.com", sn, nil))
	})

	t.Run("empty baseURL opts out", func(t *testing.T) {
		assert.Empty(t, s.URLForHash("", sn, []byte{0x01}))
	})
}

func TestBuddyIconSource_Image_RetrieveFails(t *testing.T) {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).
		Return(bartID([]byte{0x01}), nil).Once()

	bartService := newMockBARTService(t)
	bartService.EXPECT().RetrieveItem(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, errors.New("item missing")).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, BARTService: bartService, Logger: slog.Default()}
	_, err := s.Image(context.Background(), state.NewIdentScreenName("mikekelly"))

	assert.ErrorContains(t, err, "item missing")
	assert.NotErrorIs(t, err, ErrNoBuddyIcon)
}
