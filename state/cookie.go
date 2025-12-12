package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// authCookieLen is the fixed auth cookie length.
const authCookieLen = 256

// ServerCookie represents a token containing client metadata passed to the BOS
// service upon connection.
type ServerCookie struct {
	Service       uint16
	ScreenName    DisplayScreenName `oscar:"len_prefix=uint8"`
	ClientID      string            `oscar:"len_prefix=uint8"`
	ChatCookie    string            `oscar:"len_prefix=uint8"`
	MultiConnFlag uint8
	// KerberosAuth indicates whether the client used Kerberos for authentication.
	KerberosAuth uint8
	SessionNum   uint8
}

func NewHMACCookieBaker() (HMACCookieBaker, error) {
	cb := HMACCookieBaker{}
	cb.key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, cb.key); err != nil {
		return cb, fmt.Errorf("cannot generate random HMAC key: %w", err)
	}
	return cb, nil
}

type HMACCookieBaker struct {
	key []byte
}

func (c HMACCookieBaker) Issue(data []byte) ([]byte, error) {
	payload := hmacTokenPayload{
		Expiry: uint32(time.Now().Add(1 * time.Minute).Unix()),
		Data:   data,
	}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(payload, buf); err != nil {
		return nil, fmt.Errorf("unable to marshal auth authCookie: %w", err)
	}

	hmacTok := hmacToken{
		Data: buf.Bytes(),
	}
	hmacTok.hash(c.key)

	buf.Reset()

	if err := wire.MarshalBE(hmacTok, buf); err != nil {
		return nil, fmt.Errorf("unable to marshal auth authCookie: %w", err)
	}

	// Some clients (such as perl NET::OSCAR) expect the auth cookie to be
	// exactly 256 bytes, even though the cookie is stored in a
	// variable-length TLV. Pad the auth cookie to make sure it's exactly
	// 256 bytes.
	if buf.Len() > authCookieLen {
		return nil, fmt.Errorf("sess is too long, expect 256 bytes, got %d", buf.Len())
	}
	buf.Write(make([]byte, authCookieLen-buf.Len()))

	return buf.Bytes(), nil
}

func (c HMACCookieBaker) Crack(data []byte) ([]byte, error) {
	hmacTok := hmacToken{}
	if err := wire.UnmarshalBE(&hmacTok, bytes.NewBuffer(data)); err != nil {
		return nil, fmt.Errorf("unable to unmarshal HMAC cooie: %w", err)
	}

	if !hmacTok.validate(c.key) {
		return nil, errors.New("invalid HMAC cookie")
	}

	payload := hmacTokenPayload{}
	if err := wire.UnmarshalBE(&payload, bytes.NewBuffer(hmacTok.Data)); err != nil {
		return nil, fmt.Errorf("unable to unmarshal HMAC cookie payload: %w", err)
	}

	expiry := time.Unix(int64(payload.Expiry), 0)
	if expiry.Before(time.Now()) {
		return nil, errors.New("HMAC cookie expired")
	}

	return payload.Data, nil
}

type hmacTokenPayload struct {
	Expiry uint32
	Data   []byte `oscar:"len_prefix=uint16"`
}

type hmacToken struct {
	Data []byte `oscar:"len_prefix=uint16"`
	Sig  []byte `oscar:"len_prefix=uint16"`
}

func (h *hmacToken) hash(key []byte) {
	hs := hmac.New(sha256.New, key)
	if _, err := hs.Write(h.Data); err != nil {
		// according to Hash interface, Write() should never return an error
		panic("unable to compute hmac token")
	}
	h.Sig = hs.Sum(nil)
}

func (h *hmacToken) validate(key []byte) bool {
	cp := *h
	cp.hash(key)
	return hmac.Equal(h.Sig, cp.Sig)
}
