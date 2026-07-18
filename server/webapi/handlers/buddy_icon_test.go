package handlers

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

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
			iconRetriever := &MockBuddyIconRetriever{}
			iconRetriever.On("BuddyIconMetadata", mock.Anything, state.NewIdentScreenName("mikekelly")).
				Return(tt.id, tt.idErr).Once()

			s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
			got := s.URL(context.Background(), tt.baseURL, state.NewIdentScreenName("mikekelly"))

			assert.Equal(t, tt.want, got)
			iconRetriever.AssertExpectations(t)
		})
	}
}

func TestBuddyIconSource_URL_NoBaseURLSkipsLookup(t *testing.T) {
	// Callers with no origin to build an absolute URL against opt out by passing
	// an empty baseURL. That must not cost a lookup.
	iconRetriever := &MockBuddyIconRetriever{}

	s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
	got := s.URL(context.Background(), "", state.NewIdentScreenName("mikekelly"))

	assert.Empty(t, got)
	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, mock.Anything)
}

func TestBuddyIconSource_URL_UsesNormalizedScreenName(t *testing.T) {
	// The URL targets the normalized screen name, which is what the endpoint
	// resolves against and what the client keys users by.
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0x01}), nil).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
	got := s.URL(context.Background(), "http://api.example.com", state.NewIdentScreenName("Mike Kelly"))

	assert.Equal(t, "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=01", got)
}

func TestBuddyIconSource_Image(t *testing.T) {
	hash := []byte{0xde, 0xad}

	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, state.NewIdentScreenName("mikekelly")).
		Return(bartID(hash), nil).Once()

	// Image resolves the current hash from metadata, then downloads that exact
	// hash. The download query is keyed by hash; flags are irrelevant to the
	// lookup, so it carries only the type and hash.
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, wire.SNACFrame{}, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: "mikekelly",
		BARTID:     wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: hash}},
	}).Return(wire.SNACMessage{
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF},
	}, nil).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, BARTService: bartService, Logger: slog.Default()}
	got, err := s.Image(context.Background(), state.NewIdentScreenName("mikekelly"))

	assert.NoError(t, err)
	assert.Equal(t, iconGIF, got)
	iconRetriever.AssertExpectations(t)
	bartService.AssertExpectations(t)
}

func TestBuddyIconSource_ImageForHash(t *testing.T) {
	hash := []byte{0xca, 0xfe}

	// ImageForHash downloads the requested hash directly, without consulting the
	// user's current icon metadata.
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, wire.SNACFrame{}, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: "mikekelly",
		BARTID:     wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: hash}},
	}).Return(wire.SNACMessage{
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF},
	}, nil).Once()

	s := BuddyIconSource{BARTService: bartService, Logger: slog.Default()}
	got, err := s.ImageForHash(context.Background(), state.NewIdentScreenName("mikekelly"), hash)

	assert.NoError(t, err)
	assert.Equal(t, iconGIF, got)
	bartService.AssertExpectations(t)
}

func TestBuddyIconSource_ImageForHash_NotFound(t *testing.T) {
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
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
			iconRetriever := &MockBuddyIconRetriever{}
			iconRetriever.On("BuddyIconMetadata", mock.Anything, state.NewIdentScreenName("mikekelly")).
				Return(tt.id, tt.idErr).Maybe()

			s := BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()}
			got := s.PublishedURL(context.Background(), tt.baseURL, state.NewIdentScreenName("mikekelly"))

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuddyIconSource_Image_NoIcon(t *testing.T) {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).Return(nil, nil).Once()

	bartService := &MockBARTService{}

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
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0x01}), nil).Once()

	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, errors.New("item missing")).Once()

	s := BuddyIconSource{IconRetriever: iconRetriever, BARTService: bartService, Logger: slog.Default()}
	_, err := s.Image(context.Background(), state.NewIdentScreenName("mikekelly"))

	assert.ErrorContains(t, err, "item missing")
	assert.NotErrorIs(t, err, ErrNoBuddyIcon)
}
