package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/google/uuid"
)

// MaxConcurrentLoginsPerUser is the maximum number of concurrent logins allowed
// for a single user.
const MaxConcurrentLoginsPerUser = 5

// NewAuthService creates a new instance of AuthService.
func NewAuthService(
	cfg config.Config,
	sessionManager SessionRegistry,
	sessionRetriever SessionRetriever,
	chatSessionRegistry ChatSessionRegistry,
	userManager UserManager,
	cookieBaker CookieBaker,
	chatMessageRelayer ChatMessageRelayer,
	accountManager AccountManager,
	bartItemManager BARTItemManager,
	classes wire.RateLimitClasses,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		chatSessionRegistry:        chatSessionRegistry,
		config:                     cfg,
		cookieBaker:                cookieBaker,
		sessionManager:             sessionManager,
		sessionRetriever:           sessionRetriever,
		userManager:                userManager,
		chatMessageRelayer:         chatMessageRelayer,
		accountManager:             accountManager,
		bartItemManager:            bartItemManager,
		rateLimitClasses:           classes,
		timeNow:                    time.Now,
		maxConcurrentLoginsPerUser: MaxConcurrentLoginsPerUser,
		logger:                     logger,
	}
}

// AuthService provides client login and session management services. It
// supports both FLAP (AIM v1.0-v3.0) and BUCP (AIM v3.5-v5.9) authentication
// modes.
type AuthService struct {
	chatMessageRelayer         ChatMessageRelayer
	chatSessionRegistry        ChatSessionRegistry
	config                     config.Config
	cookieBaker                CookieBaker
	logger                     *slog.Logger
	sessionManager             SessionRegistry
	sessionRetriever           SessionRetriever
	userManager                UserManager
	accountManager             AccountManager
	bartItemManager            BARTItemManager
	rateLimitClasses           wire.RateLimitClasses
	timeNow                    func() time.Time
	maxConcurrentLoginsPerUser int
}

// RegisterChatSession adds a user to a chat room. The authCookie param is an
// opaque token returned by {{OServiceService.ServiceRequest}} that identifies
// the user and chat room. It returns the session object registered in the
// ChatSessionRegistry.
// This method does not verify that the user and chat room exist because it
// implicitly trusts the contents of the token signed by
// {{OServiceService.ServiceRequest}}.
func (s AuthService) RegisterChatSession(ctx context.Context, serverCookie state.ServerCookie) (*state.SessionInstance, error) {
	sess, err := s.chatSessionRegistry.AddSession(ctx, serverCookie.ChatCookie, serverCookie.ScreenName)
	if err != nil {
		return nil, fmt.Errorf("AddSession: %w", err)
	}

	sess.Session().SetRateClasses(time.Now(), s.rateLimitClasses)

	return sess, err
}

func (s AuthService) CrackCookie(authCookie []byte) (state.ServerCookie, error) {
	c := state.ServerCookie{}

	buf, err := s.cookieBaker.Crack(authCookie)
	if err != nil {
		return c, err
	}

	if err := wire.UnmarshalBE(&c, bytes.NewBuffer(buf)); err != nil {
		return c, err
	}

	return c, nil
}

// RegisterBOSSession adds a new session to the session registry.
func (s AuthService) RegisterBOSSession(ctx context.Context, serverCookie state.ServerCookie) (*state.SessionInstance, error) {
	u, err := s.userManager.User(ctx, serverCookie.ScreenName.IdentScreenName())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	flag := wire.MultiConnFlag(serverCookie.MultiConnFlag)

	doMultiSess := false
	if flag == wire.MultiConnFlagsRecentClient {
		doMultiSess = true
	}

	sess, err := s.sessionManager.AddSession(ctx, u.DisplayScreenName, doMultiSess)
	if err != nil {
		return nil, fmt.Errorf("AddSession: %w", err)
	}

	// set the unconfirmed user info flag if this account is unconfirmed
	if confirmed, err := s.accountManager.ConfirmStatus(ctx, sess.IdentScreenName()); err != nil {
		return nil, fmt.Errorf("error setting unconfirmed user flag: %w", err)
	} else if !confirmed {
		sess.SetUserInfoFlag(wire.OServiceUserFlagUnconfirmed)
	}

	if u.IsBot {
		sess.SetUserInfoFlag(wire.OServiceUserFlagBot)
	}

	sess.SetKerberosAuth(serverCookie.KerberosAuth == 1)
	sess.Session().SetSignonTime(time.Now())
	sess.Session().SetRateClasses(time.Now(), s.rateLimitClasses)
	// set string containing OSCAR client name and version
	sess.SetClientID(serverCookie.ClientID)
	sess.Session().SetMemberSince(time.Now())
	sess.Session().SetOfflineMsgCount(u.OfflineMsgCount)

	if _, alreadySet := sess.Session().BuddyIcon(); !alreadySet {
		bartID, err := s.bartItemManager.BuddyIconMetadata(ctx, sess.IdentScreenName())
		if err != nil {
			return nil, fmt.Errorf("BuddyIconMetadata: %w", err)
		}
		if bartID != nil {
			sess.Session().SetBuddyIcon(*bartID)
		}
	}

	// indicate whether the client supports/wants multiple concurrent sessions
	sess.SetMultiConnFlag(flag)

	if u.DisplayScreenName.IsUIN() {
		sess.SetUserInfoFlag(wire.OServiceUserFlagICQ)

		uin, err := strconv.Atoi(u.IdentScreenName.String())
		if err != nil {
			return nil, fmt.Errorf("error converting username to UIN: %w", err)
		}
		sess.Session().SetUIN(uint32(uin))
	}

	return sess, nil
}

// RetrieveBOSSession returns a user's existing session instance
func (s AuthService) RetrieveBOSSession(ctx context.Context, serverCookie state.ServerCookie) (*state.SessionInstance, error) {
	u, err := s.userManager.User(ctx, serverCookie.ScreenName.IdentScreenName())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	sess := s.sessionRetriever.RetrieveSession(u.IdentScreenName)
	if sess == nil {
		return nil, nil
	}

	return sess.Instance(serverCookie.SessionNum), nil
}

// Signout removes this user's session.
func (s AuthService) Signout(ctx context.Context, instance *state.SessionInstance) {
	s.sessionManager.RemoveSession(instance)
}

// SignoutChat removes user from chat room and notifies remaining participants
// of their departure.
func (s AuthService) SignoutChat(ctx context.Context, instance *state.SessionInstance) {
	alertUserLeft(ctx, instance, s.chatMessageRelayer)
	s.chatSessionRegistry.RemoveSession(instance)
}

// BUCPChallenge processes a BUCP authentication challenge request. It
// retrieves the user's auth key based on the screen name provided in the
// request. The client uses the auth key to salt the MD5 password hash provided
// in the subsequent login request. If the account is valid, return
// SNAC(0x17,0x07), otherwise return SNAC(0x17,0x03).
func (s AuthService) BUCPChallenge(ctx context.Context, inBody wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error) {

	screenName, exists := inBody.String(wire.LoginTLVTagsScreenName)
	if !exists {
		s.logger.Debug("BUCPChallenge: screen name TLV not found in request")
		return wire.SNACMessage{}, errors.New("screen name doesn't exist in tlv")
	}

	s.logger.Debug("BUCPChallenge: received challenge request",
		"screen_name", screenName,
		"is_uin", state.DisplayScreenName(screenName).IsUIN())

	var authKey string

	user, err := s.userManager.User(ctx, state.NewIdentScreenName(screenName))
	if err != nil {
		s.logger.Error("BUCPChallenge: user lookup failed", "screen_name", screenName, "err", err.Error())
		return wire.SNACMessage{}, err
	}

	switch {
	case user != nil:
		// user lookup succeeded
		authKey = user.AuthKey
		s.logger.Debug("BUCPChallenge: user found, returning auth key",
			"screen_name", screenName,
			"auth_key_len", len(authKey))
	case s.config.DisableAuth:
		// can't find user, generate stub auth key
		authKey = newUUID().String()
		s.logger.Debug("BUCPChallenge: user not found, auth disabled, generating stub auth key",
			"screen_name", screenName)
	default:
		// can't find user, return login error
		s.logger.Debug("BUCPChallenge: user not found, returning error",
			"screen_name", screenName,
			"error_code", wire.LoginErrInvalidUsernameOrPassword)
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BUCP,
				SubGroup:  wire.BUCPLoginResponse,
			},
			Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: []wire.TLV{
						wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
					},
				},
			},
		}, nil
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPChallengeResponse,
		},
		Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{
			AuthKey: authKey,
		},
	}, nil
}

// BUCPLogin processes a BUCP authentication request for AIM v3.5-v5.9. Upon
// successful login, a session is created.
// If login credentials are invalid and app config DisableAuth is true, a stub
// user is created and login continues as normal. DisableAuth allows you to
// skip the account creation procedure, which simplifies the login flow during
// development.
// If login is successful, the SNAC TLV list contains the BOS server address
// (wire.LoginTLVTagsReconnectHere) and an authorization cookie
// (wire.LoginTLVTagsAuthorizationCookie). Else, an error code is set
// (wire.LoginTLVTagsErrorSubcode).
func (s AuthService) BUCPLogin(ctx context.Context, inBody wire.SNAC_0x17_0x02_BUCPLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string, advertisedHostSSL string) (wire.SNACMessage, error) {

	block, err := s.login(ctx, inBody.TLVList, newUserFn, advertisedHost, advertisedHostSSL)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPLoginResponse,
		},
		Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
			TLVRestBlock: block,
		},
	}, nil
}

// FLAPLogin processes a FLAP authentication request for AIM v1.0-v3.0. Upon
// successful login, a session is created.
// If login credentials are invalid and app config DisableAuth is true, a stub
// user is created and login continues as normal. DisableAuth allows you to
// skip the account creation procedure, which simplifies the login flow during
// development.
// If login is successful, the SNAC TLV list contains the BOS server address
// (wire.LoginTLVTagsReconnectHere) and an authorization cookie
// (wire.LoginTLVTagsAuthorizationCookie). Else, an error code is set
// (wire.LoginTLVTagsErrorSubcode).
func (s AuthService) FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string, advertisedHostSSL string) (wire.TLVRestBlock, error) {
	return s.login(ctx, inFrame.TLVList, newUserFn, advertisedHost, advertisedHostSSL)
}

// KerberosLogin handles AIM-style Kerberos authentication for AIM 6.0+.
// Credit for understanding the SNAC structure and values goes to this mailing
// list attachment from 2007:
//
//	https://web.archive.org/web/20100619063015/http://pidgin.im/pipermail/devel/attachments/20070906/e0069ff5/attachment-0001.txt
//
// Several values in the response are poorly understood but necessary for proper
// processing on the client side.
func (s AuthService) KerberosLogin(ctx context.Context, inBody wire.SNAC_0x050C_0x0002_KerberosLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string, advertisedHostSSL string) (wire.SNACMessage, error) {

	b, ok := inBody.TicketRequestMetadata.Bytes(wire.KerberosTLVTicketRequest)
	if !ok {
		return wire.SNACMessage{}, fmt.Errorf("ticket request metadata bytes is missing")
	}

	var info wire.KerberosLoginRequestTicket
	if err := wire.UnmarshalBE(&info, bytes.NewReader(b)); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("ticket request metadata unmarshal: %w", err)
	}

	list := wire.TLVList{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, inBody.ClientPrincipal),
		wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
	}

	if info.Version >= 4 {
		list = append(list, wire.NewTLVBE(wire.LoginTLVTagsRoastedKerberosPassword, info.Password))
	} else {
		list = append(list, wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, info.Password))
	}

	result, err := s.login(ctx, list, newUserFn, advertisedHost, advertisedHostSSL)
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("login: %w", err)
	}

	cookie, loginOK := result.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !loginOK {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Kerberos,
				SubGroup:  wire.KerberosKerberosLoginErrResponse,
			},
			Body: wire.SNAC_0x050C_0x0004_KerberosLoginErrResponse{
				KerbRequestID: inBody.RequestID,
				ScreenName:    inBody.ClientPrincipal,
				ErrCode:       wire.KerberosErrAuthFailure,
				Message:       "Auth failure",
			},
		}, nil
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Kerberos,
			SubGroup:  wire.KerberosLoginSuccessResponse,
		},
		Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
			RequestID:       inBody.RequestID,
			Epoch:           uint32(s.timeNow().Unix()),
			ClientPrincipal: inBody.ClientPrincipal,
			ClientRealm:     "AOL",
			Tickets: []wire.KerberosTicket{
				{
					PVNO:             5,
					EncTicket:        []byte{},
					TicketRealm:      "AOL",
					ServicePrincipal: "im/boss",
					ClientRealm:      "AOL",
					ClientPrincipal:  inBody.ClientPrincipal,
					AuthTime:         uint32(s.timeNow().Unix()),
					StartTime:        uint32(s.timeNow().Unix()),
					EndTime:          uint32(s.timeNow().Add(24 * time.Hour).Unix()),
					Unknown4:         1610612736,
					Unknown5:         1073741824,
					ConnectionMetadata: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.KerberosTLVBOSServerInfo, wire.KerberosBOSServerInfo{
								Unknown: 1,
								ConnectionInfo: wire.TLVBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.KerberosTLVHostname, advertisedHost),
										wire.NewTLVBE(wire.KerberosTLVCookie, cookie),
										wire.NewTLVBE(wire.KerberosTLVConnSettings, wire.KerberosConnUseSSL),
									},
								},
							}),
						},
					},
				},
			},
		},
	}, nil
}

// loginProperties represents the properties sent by the client at login.
type loginProperties struct {
	clientID                string
	isBUCPAuth              bool
	isFLAPAuth              bool
	isFLAPJavaAuth          bool
	isKerberosPlaintextAuth bool
	isKerberosRoastedAuth   bool
	isTOCAuth               bool
	multiConnFlag           uint8
	passwordHash            []byte
	plaintextPassword       []byte
	roastedPass             []byte
	screenName              state.DisplayScreenName
}

// fromTLV creates an instance of loginProperties from a TLV list.
func (l *loginProperties) fromTLV(list wire.TLVList) error {
	// extract screen name
	if screenName, found := list.String(wire.LoginTLVTagsScreenName); found {
		l.screenName = state.DisplayScreenName(screenName)
	} else {
		return errors.New("screen name doesn't exist in tlv")
	}

	// extract client name and version
	if clientID, found := list.String(wire.LoginTLVTagsClientIdentity); found {
		l.clientID = clientID
	}

	// get the password from the appropriate TLV. older clients have a
	// roasted password, newer clients have a hashed password. ICQ may omit
	// the password TLV when logging in without saved password.
	switch {
	case list.HasTag(wire.LoginTLVTagsPasswordHash):
		// extract password hash for BUCP login
		l.passwordHash, _ = list.Bytes(wire.LoginTLVTagsPasswordHash)
		l.isBUCPAuth = true
	case list.HasTag(wire.LoginTLVTagsRoastedPassword):
		// extract roasted password for FLAP login
		l.roastedPass, _ = list.Bytes(wire.LoginTLVTagsRoastedPassword)
		if strings.HasPrefix(l.clientID, "AOL Instant Messenger (TM) version") &&
			strings.Contains(l.clientID, "for Java") {
			l.isFLAPJavaAuth = true
		} else {
			l.isFLAPAuth = true
		}
	case list.HasTag(wire.LoginTLVTagsRoastedTOCPassword):
		// extract roasted password for TOC FLAP login
		l.roastedPass, _ = list.Bytes(wire.LoginTLVTagsRoastedTOCPassword)
		l.isTOCAuth = true
	case list.HasTag(wire.LoginTLVTagsPlaintextPassword):
		l.plaintextPassword, _ = list.Bytes(wire.LoginTLVTagsPlaintextPassword)
		l.isKerberosPlaintextAuth = true
	case list.HasTag(wire.LoginTLVTagsRoastedKerberosPassword):
		l.roastedPass, _ = list.Bytes(wire.LoginTLVTagsRoastedKerberosPassword)
		l.isKerberosRoastedAuth = true
	default:
		l.isFLAPAuth = true
	}

	// does the client support multiple concurrent sessions?
	if multiConnFlags, found := list.Uint8(wire.LoginTLVTagsMultiConnFlags); found {
		l.multiConnFlag = multiConnFlags
	}

	return nil
}

// login validates a user's credentials and creates their session. it returns
// metadata used in both BUCP and FLAP authentication responses.
func (s AuthService) login(ctx context.Context, tlv wire.TLVList, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string, advertisedHostSSL string) (wire.TLVRestBlock, error) {

	props := loginProperties{}
	if err := props.fromTLV(tlv); err != nil {
		s.logger.Debug("login: failed to parse TLVs", "err", err.Error())
		return wire.TLVRestBlock{}, err
	}

	s.logger.Debug("login: parsed login properties",
		"screen_name", props.screenName,
		"client_id", props.clientID,
		"is_bucp", props.isBUCPAuth,
		"is_flap", props.isFLAPAuth,
		"is_flap_java", props.isFLAPJavaAuth,
		"is_toc", props.isTOCAuth,
		"is_kerberos_plaintext", props.isKerberosPlaintextAuth,
		"is_kerberos_roasted", props.isKerberosRoastedAuth,
		"password_hash_len", len(props.passwordHash),
		"roasted_pass_len", len(props.roastedPass))

	user, err := s.userManager.User(ctx, props.screenName.IdentScreenName())
	if err != nil {
		s.logger.Error("login: user lookup failed", "screen_name", props.screenName, "err", err.Error())
		return wire.TLVRestBlock{}, err
	}

	if user == nil {
		s.logger.Debug("login: user not found", "screen_name", props.screenName)
		// user not found
		if s.config.DisableAuth {
			// auth disabled, create the user
			s.logger.Debug("login: auth disabled, creating user", "screen_name", props.screenName)
			return s.createUser(ctx, props, newUserFn, advertisedHost, advertisedHostSSL)
		}
		// auth enabled, return separate login errors for ICQ and AIM
		loginErr := wire.LoginErrInvalidUsernameOrPassword
		if props.screenName.IsUIN() {
			loginErr = wire.LoginErrICQUserErr
		}
		s.logger.Debug("login: returning user not found error",
			"screen_name", props.screenName,
			"error_code", loginErr)
		return loginFailureResponse(props, loginErr), nil
	}

	s.logger.Debug("login: user found", "screen_name", props.screenName, "is_icq", user.IsICQ)

	// check if suspended status should prevent login
	if user.SuspendedStatus > 0x0 {
		s.logger.Debug("login: user suspended",
			"screen_name", props.screenName,
			"suspended_status", user.SuspendedStatus)
		return loginFailureResponse(props, user.SuspendedStatus), nil
	}

	if s.config.DisableAuth {
		// user exists, but don't validate
		s.logger.Debug("login: auth disabled, skipping password validation", "screen_name", props.screenName)
		return s.loginSuccessResponse(props, advertisedHost, advertisedHostSSL)
	}

	var loginOK bool
	var authMethod string
	switch {
	case props.isBUCPAuth:
		authMethod = "BUCP"
		loginOK = user.ValidateHash(props.passwordHash)
	case props.isFLAPAuth:
		authMethod = "FLAP"
		loginOK = user.ValidateRoastedPass(props.roastedPass)
	case props.isFLAPJavaAuth:
		authMethod = "FLAP_Java"
		loginOK = user.ValidateRoastedJavaPass(props.roastedPass)
	case props.isTOCAuth:
		authMethod = "TOC"
		loginOK = user.ValidateRoastedTOCPass(props.roastedPass)
	case props.isKerberosPlaintextAuth:
		authMethod = "Kerberos_Plaintext"
		loginOK = user.ValidatePlaintextPass(props.plaintextPassword)
	case props.isKerberosRoastedAuth:
		authMethod = "Kerberos_Roasted"
		loginOK = user.ValidateRoastedKerberosPass(props.roastedPass)
	}

	s.logger.Debug("login: password validation result",
		"screen_name", props.screenName,
		"auth_method", authMethod,
		"login_ok", loginOK)

	if !loginOK {
		s.logger.Debug("login: password validation failed",
			"screen_name", props.screenName,
			"auth_method", authMethod)
		return loginFailureResponse(props, wire.LoginErrInvalidPassword), nil
	}

	// limit concurrent logins per user
	if props.multiConnFlag == uint8(wire.MultiConnFlagsRecentClient) {
		sess := s.sessionRetriever.RetrieveSession(props.screenName.IdentScreenName())
		if sess != nil && sess.InstanceCount() >= s.maxConcurrentLoginsPerUser {
			s.logger.Debug("login: too many concurrent sessions",
				"screen_name", props.screenName,
				"instance_count", sess.InstanceCount())
			return loginFailureResponse(props, wire.LoginErrRateLimitExceeded), nil
		}
	}

	s.logger.Debug("login: login successful", "screen_name", props.screenName)
	return s.loginSuccessResponse(props, advertisedHost, advertisedHostSSL)
}

func (s AuthService) createUser(ctx context.Context, props loginProperties, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string, advertisedHostSSL string) (wire.TLVRestBlock, error) {

	var err error
	if props.screenName.IsUIN() {
		err = props.screenName.ValidateUIN()
	} else {
		err = props.screenName.ValidateAIMHandle()
	}

	if err != nil {
		switch {
		case errors.Is(err, state.ErrAIMHandleInvalidFormat) || errors.Is(err, state.ErrAIMHandleLength):
			return loginFailureResponse(props, wire.LoginErrInvalidUsernameOrPassword), nil
		case errors.Is(err, state.ErrICQUINInvalidFormat):
			return loginFailureResponse(props, wire.LoginErrICQUserErr), nil
		default:
			return wire.TLVRestBlock{}, err
		}
	}

	newUser, err := newUserFn(props.screenName)
	if err != nil {
		return wire.TLVRestBlock{}, err
	}

	err = s.userManager.InsertUser(ctx, newUser)
	if err != nil {
		return wire.TLVRestBlock{}, err
	}

	return s.loginSuccessResponse(props, advertisedHost, advertisedHostSSL)
}

func (s AuthService) loginSuccessResponse(props loginProperties, advertisedHost string, advertisedHostSSL string) (wire.TLVRestBlock, error) {
	loginCookie := state.ServerCookie{
		Service:       wire.BOS,
		ScreenName:    props.screenName,
		ClientID:      props.clientID,
		MultiConnFlag: props.multiConnFlag,
	}
	if props.isKerberosPlaintextAuth || props.isKerberosRoastedAuth {
		loginCookie.KerberosAuth = 1
	}

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(loginCookie, buf); err != nil {
		return wire.TLVRestBlock{}, err
	}
	cookie, err := s.cookieBaker.Issue(buf.Bytes())
	if err != nil {
		return wire.TLVRestBlock{}, fmt.Errorf("failed to issue auth cookie: %w", err)
	}

	reconnectHost := advertisedHost
	sslState := wire.OServiceServiceResponseSSLStateNotUsed

	s.logger.Debug("loginSuccessResponse: returning login response",
		"screen_name", props.screenName,
		"reconnect_host", reconnectHost,
		"ssl_state", sslState)

	return wire.TLVRestBlock{
		TLVList: []wire.TLV{
			wire.NewTLVBE(wire.LoginTLVTagsScreenName, props.screenName),
			wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, reconnectHost),
			wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, cookie),
			wire.NewTLVBE(wire.OServiceTLVTagsSSLState, sslState),
		},
	}, nil
}

func loginFailureResponse(props loginProperties, errCode uint16) wire.TLVRestBlock {
	return wire.TLVRestBlock{
		TLVList: []wire.TLV{
			wire.NewTLVBE(wire.LoginTLVTagsScreenName, props.screenName),
			wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, errCode),
		},
	}
}
