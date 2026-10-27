package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// DefaultClientIdentity is the client identity string sent at login.
const DefaultClientIdentity = "Open OSCAR Go Client"

// LoginError indicates that the server rejected a login attempt.
type LoginError struct {
	Code uint16
}

func (e *LoginError) Error() string {
	switch e.Code {
	case wire.LoginErrInvalidUsernameOrPassword, wire.LoginErrInvalidPassword:
		return "incorrect screen name or password"
	case wire.LoginErrSuspendedAccount, wire.LoginErrSuspendedAccountAge:
		return "account is suspended"
	case wire.LoginErrDeletedAccount:
		return "account has been deleted"
	case wire.LoginErrExpiredAccount:
		return "account has expired"
	case wire.LoginErrRateLimitExceeded:
		return "connecting too frequently, wait a few minutes and try again"
	case wire.LoginErrTooHeavilyWarned:
		return "warning level too high to sign on"
	case wire.LoginErrInternalClientError:
		return "server rejected the login request"
	default:
		return fmt.Sprintf("login failed (code 0x%04X)", e.Code)
	}
}

// loginResult is a successful login's BOS server address and login cookie.
type loginResult struct {
	bosAddr string
	cookie  []byte
}

// bucpLogin signs on to the auth service at addr with BUCP (MD5 challenge)
// authentication.
func bucpLogin(ctx context.Context, addr, screenName, password, clientID string) (loginResult, error) {
	nc, err := dial(ctx, addr)
	if err != nil {
		return loginResult{}, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = nc.Close() }()

	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = nc.SetDeadline(deadline)

	flapc := wire.NewFlapClient(0, nc, nc)
	if _, err := flapc.ReceiveSignonFrame(); err != nil {
		return loginResult{}, fmt.Errorf("ReceiveSignonFrame: %w", err)
	}
	if err := flapc.SendSignonFrame(nil); err != nil {
		return loginResult{}, fmt.Errorf("SendSignonFrame: %w", err)
	}

	challenge := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
	challenge.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName))
	if err := flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPChallengeRequest, RequestID: 1}, challenge); err != nil {
		return loginResult{}, fmt.Errorf("send challenge request: %w", err)
	}

	msg, err := receiveAuthSNAC(flapc)
	if err != nil {
		return loginResult{}, err
	}
	var authKey string
	switch body := msg.Body.(type) {
	case wire.SNAC_0x17_0x07_BUCPChallengeResponse:
		authKey = body.AuthKey
	case wire.SNAC_0x17_0x03_BUCPLoginResponse:
		return loginResult{}, loginResponseErr(body.TLVRestBlock)
	default:
		return loginResult{}, fmt.Errorf("unexpected challenge reply %s",
			wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
	}

	login := wire.SNAC_0x17_0x02_BUCPLoginRequest{}
	login.AppendList([]wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName),
		wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, wire.StrongMD5PasswordHash(password, authKey)),
		wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, clientID),
		wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, uint8(wire.MultiConnFlagsRecentClient)),
	})
	if err := flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginRequest, RequestID: 2}, login); err != nil {
		return loginResult{}, fmt.Errorf("send login request: %w", err)
	}

	msg, err = receiveAuthSNAC(flapc)
	if err != nil {
		return loginResult{}, err
	}
	resp, ok := msg.Body.(wire.SNAC_0x17_0x03_BUCPLoginResponse)
	if !ok {
		return loginResult{}, fmt.Errorf("unexpected login reply %s",
			wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
	}
	if err := loginResponseErr(resp.TLVRestBlock); err != nil {
		return loginResult{}, err
	}

	bosAddr, hasAddr := resp.String(wire.LoginTLVTagsReconnectHere)
	cookie, hasCookie := resp.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !hasAddr || !hasCookie {
		return loginResult{}, errors.New("login response is missing the BOS address or cookie")
	}
	return loginResult{bosAddr: bosAddr, cookie: cookie}, nil
}

// receiveAuthSNAC receives the next SNAC from the auth service.
func receiveAuthSNAC(flapc *wire.FlapClient) (wire.SNACMessage, error) {
	for {
		frame, err := flapc.ReceiveFLAP()
		if err != nil {
			return wire.SNACMessage{}, fmt.Errorf("ReceiveFLAP: %w", err)
		}
		switch frame.FrameType {
		case wire.FLAPFrameData:
			return decodeSNAC(frame.Payload)
		case wire.FLAPFrameSignoff:
			var se *SignoffError
			if errors.As(signoffErr(frame.Payload), &se) {
				return wire.SNACMessage{}, &LoginError{Code: se.Code}
			}
			return wire.SNACMessage{}, errors.New("auth server closed the connection")
		}
	}
}

// loginResponseErr returns a *LoginError if the login response carries an
// error code.
func loginResponseErr(block wire.TLVRestBlock) error {
	if code, failed := block.Uint16BE(wire.LoginTLVTagsErrorSubcode); failed {
		return &LoginError{Code: code}
	}
	return nil
}
