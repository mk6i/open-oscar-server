package icq_legacy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ICQLegacyService provides the service layer for legacy ICQ protocols (v2-v5).
// It bridges legacy protocol handlers with the existing infrastructure, implementing
// the LegacyService interface defined in server/icq_legacy/handler.go.
//
// Following the OSCAR foodgroup architecture pattern, this service contains all
// business logic (authentication, messaging, contact list processing, status changes,
// user info retrieval) while protocol handlers remain thin routing layers.
//
// Service methods accept typed request structs and return typed response structs,
// keeping the service layer protocol-independent. Handlers are responsible for
// parsing protocol-specific packets into request structs and building
// protocol-specific response packets from the returned result structs.
type ICQLegacyService struct {
	authService                AuthService
	userManager                UserManager
	accountManager             AccountManager
	sessionRetriever           SessionRetriever
	messageRelayer             MessageRelayer
	buddyBroadcaster           BuddyBroadcaster
	offlineMessageManager      OfflineMessageManager
	icbmService                ICBMService
	userFinder                 ICQUserFinder
	userUpdater                ICQUserUpdater
	feedbagManager             FeedbagManager
	relationshipFetcher        RelationshipFetcher
	buddyListRegistry          BuddyListRegistry
	clientSideBuddyListManager ClientSideBuddyListManager
	logger                     *slog.Logger
	timeNow                    func() time.Time

	// legacySessionManager is set by the server package
	legacySessionManager *LegacySessionManager
}

// NewICQLegacyService creates a new ICQLegacyService with the given dependencies.
// The legacy session manager must be set separately via SetLegacySessionManager
// after the server package initializes it, to avoid circular dependencies.
func NewICQLegacyService(
	authService AuthService,
	userManager UserManager,
	accountManager AccountManager,
	sessionRetriever SessionRetriever,
	messageRelayer MessageRelayer,
	buddyBroadcaster BuddyBroadcaster,
	offlineMessageManager OfflineMessageManager,
	userFinder ICQUserFinder,
	userUpdater ICQUserUpdater,
	feedbagManager FeedbagManager,
	relationshipFetcher RelationshipFetcher,
	buddyListRegistry BuddyListRegistry,
	clientSideBuddyListManager ClientSideBuddyListManager,
	icbmSvc ICBMService,
	logger *slog.Logger,
) *ICQLegacyService {
	return &ICQLegacyService{
		authService:                authService,
		userManager:                userManager,
		accountManager:             accountManager,
		sessionRetriever:           sessionRetriever,
		messageRelayer:             messageRelayer,
		buddyBroadcaster:           buddyBroadcaster,
		offlineMessageManager:      offlineMessageManager,
		userFinder:                 userFinder,
		userUpdater:                userUpdater,
		feedbagManager:             feedbagManager,
		relationshipFetcher:        relationshipFetcher,
		buddyListRegistry:          buddyListRegistry,
		clientSideBuddyListManager: clientSideBuddyListManager,
		icbmService:                icbmSvc,
		logger:                     logger,
		timeNow:                    time.Now,
	}
}

// SetLegacySessionManager sets the legacy session manager used for checking
// online status and determining notification targets. This is called by the
// server package after initialization to break the circular dependency between
// the foodgroup and server/icq_legacy packages.
func (s *ICQLegacyService) SetLegacySessionManager(mgr *LegacySessionManager) {
	s.legacySessionManager = mgr
}

// ValidateCredentials checks if the given UIN and password are valid.
// Returns true if credentials are valid, false otherwise.
// The password is validated by AuthService without registering a BOS session.
func (s *ICQLegacyService) ValidateCredentials(ctx context.Context, uin uint32, password string) (bool, error) {
	if uin == 0 {
		return false, nil
	}
	block, err := s.legacyFLAPLogin(ctx, uin, password)
	if err != nil {
		if errors.Is(err, state.ErrNoUser) {
			return false, nil
		}
		return false, fmt.Errorf("AuthService.FLAPLogin: %w", err)
	}

	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		s.logger.Debug("credentials validation failed", "uin", uin)
		return false, nil
	}

	s.logger.Debug("credentials validated successfully", "uin", uin)
	return true, nil
}

// AuthenticateUser validates user credentials and returns authentication result.
// This is the service layer method for authentication that handlers call after
// parsing login packets. It validates credentials and returns a typed result
// struct containing success/failure and session data.
//
// The method does NOT contain any protocol-specific packet building logic.
// Handlers are responsible for building protocol-specific responses based on
// the returned AuthResult.
func (s *ICQLegacyService) AuthenticateUser(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	result := &AuthResult{
		Success:   false,
		ErrorCode: 0x0001, // Default to bad password error
	}

	// Validate that UIN is provided
	if req.UIN == 0 {
		s.logger.Debug("authentication failed - no UIN provided")
		result.ErrorCode = 0x0002 // User not found
		return result, nil
	}

	block, err := s.legacyFLAPLogin(ctx, req.UIN, req.Password)
	if err != nil {
		if errors.Is(err, state.ErrNoUser) {
			s.logger.Debug("authentication failed - user not found", "uin", req.UIN)
			result.ErrorCode = 0x0002 // User not found
			return result, nil
		}
		return nil, fmt.Errorf("AuthService.FLAPLogin: %w", err)
	}

	if errCode, ok := block.Uint16BE(wire.LoginTLVTagsErrorSubcode); ok {
		s.logger.Debug("authentication failed",
			"uin", req.UIN,
			"error_code", fmt.Sprintf("0x%04X", errCode),
		)
		if errCode == wire.LoginErrICQUserErr {
			result.ErrorCode = 0x0002 // User not found
		}
		return result, nil
	}

	authCookie, ok := block.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		return nil, fmt.Errorf("authorization cookie missing from auth response")
	}

	serverCookie, err := s.authService.CrackCookie(authCookie)
	if err != nil {
		return nil, fmt.Errorf("AuthService.CrackCookie: %w", err)
	}

	instance, err := s.authService.RegisterBOSSession(ctx, serverCookie, func(sess *state.Session) {
		sess.OnSessionClose(func() {
			if s.legacySessionManager != nil {
				s.legacySessionManager.RemoveSession(req.UIN)
			}
		})
	})
	if err != nil {
		return nil, fmt.Errorf("AuthService.RegisterBOSSession: %w", err)
	}
	if instance == nil {
		s.logger.Debug("authentication failed - missing OSCAR session", "uin", req.UIN)
		return result, nil
	}

	// Authentication successful
	result.Success = true
	result.ErrorCode = 0 // Success
	result.SessionID = uuid.New().String()
	result.oscarSession = instance

	s.logger.Info("user authenticated successfully",
		"uin", req.UIN,
		"version", req.Version,
		"status", fmt.Sprintf("0x%08X", req.Status),
	)

	return result, nil
}

func (s *ICQLegacyService) legacyFLAPLogin(ctx context.Context, uin uint32, password string) (wire.TLVRestBlock, error) {
	screenName := strconv.FormatUint(uint64(uin), 10)
	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	return s.authService.FLAPLogin(ctx, signonFrame, "")
}

// ProcessContactList processes a contact list and returns online status for each contact.
// This is the service layer method for contact list processing that handlers call after
// parsing contact list packets. It checks the online status of each contact and returns
// a ContactListResult containing the status of each contact.
//
// The method does NOT contain any protocol-specific packet building logic.
// Handlers are responsible for:
// - Parsing protocol-specific contact list packets into ContactListRequest
// - Using the returned ContactListResult to send online/offline notifications
// - Building protocol-specific response packets
func (s *ICQLegacyService) ProcessContactList(ctx context.Context, req ContactListRequest) (*ContactListResult, error) {
	result := &ContactListResult{
		OnlineContacts: make([]ContactStatus, 0, len(req.Contacts)),
	}

	// Validate request
	if req.UIN == 0 {
		s.logger.Debug("ProcessContactList: invalid owner UIN")
		return result, nil
	}

	s.logger.Debug("ProcessContactList: processing contact list",
		"owner_uin", req.UIN,
		"contact_count", len(req.Contacts),
	)

	// Sync legacy contact list to clientSideBuddyList so the OSCAR
	// relationship query (AllRelationships) can discover this legacy user's
	// contacts. Legacy clients use client-side buddy lists, not feedbag.
	// Write both directions: forward (me has them) and reverse (them has me)
	// so that OSCAR clients using feedbag can also discover the legacy user
	// via the relationship query's clientSideBuddyList path.
	ownerScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.UIN), 10))
	for _, contactUIN := range req.Contacts {
		contactName := state.NewIdentScreenName(strconv.FormatUint(uint64(contactUIN), 10))
		// Forward: owner has contact on their list
		if err := s.clientSideBuddyListManager.AddBuddy(ctx, ownerScreenName, contactName); err != nil {
			s.logger.Error("ProcessContactList: failed to add buddy to client-side list",
				"owner_uin", req.UIN,
				"contact_uin", contactUIN,
				"err", err,
			)
		}
		// Reverse: contact has owner on their list (so OSCAR clients see the legacy user).
		// Only add if the contact does NOT require authorization — otherwise the
		// legacy user must go through the auth request flow first.
		contactUser, userErr := s.userFinder.FindByUIN(ctx, contactUIN)
		if userErr == nil && !contactUser.ICQPermissions.AuthRequired {
			if err := s.clientSideBuddyListManager.AddBuddy(ctx, contactName, ownerScreenName); err != nil {
				s.logger.Error("ProcessContactList: failed to add reverse buddy entry",
					"owner_uin", req.UIN,
					"contact_uin", contactUIN,
					"err", err,
				)
			}
		} else if userErr != nil {
			// User not found or error — add reverse entry anyway (permissive default)
			if err := s.clientSideBuddyListManager.AddBuddy(ctx, contactName, ownerScreenName); err != nil {
				s.logger.Error("ProcessContactList: failed to add reverse buddy entry",
					"owner_uin", req.UIN,
					"contact_uin", contactUIN,
					"err", err,
				)
			}
		}
	}

	// Check online status for each contact
	for _, contactUIN := range req.Contacts {
		status := ContactStatus{
			UIN:     contactUIN,
			Online:  false,
			Status:  0,
			Version: 0,
		}

		// Check if contact is online via legacy session manager
		if s.legacySessionManager != nil {
			legacySession := s.legacySessionManager.GetSession(contactUIN)
			if legacySession != nil {
				// Check visibility — invisible users should not appear online
				// unless the viewer is on their visible list
				contactStatus := legacySession.GetStatus()
				visible := true
				if contactStatus&ICQLegacyStatusInvisible != 0 {
					visible = legacySession.IsOnVisibleList(req.UIN)
				}
				if visible {
					status.Online = true
					status.Status = contactStatus
					s.logger.Debug("ProcessContactList: contact online (legacy)",
						"contact_uin", contactUIN,
						"status", fmt.Sprintf("0x%08X", status.Status),
					)
				}
			}
		}

		// If not found in legacy sessions, check OSCAR sessions
		if !status.Online {
			contactScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(contactUIN), 10))
			oscarSession := s.sessionRetriever.RetrieveSession(contactScreenName)
			if oscarSession != nil {
				status.Online = true
				// Read actual OSCAR status and map to legacy
				userInfo := oscarSession.TLVUserInfo()
				oscarStatusVal, _ := userInfo.Uint32BE(wire.OServiceUserInfoStatus)
				status.Status = mapOSCARStatusToLegacy(oscarStatusVal)
				status.Version = 0 // OSCAR client, not legacy
				s.logger.Debug("ProcessContactList: contact online (OSCAR)",
					"contact_uin", contactUIN,
					"status", fmt.Sprintf("0x%08X", status.Status),
				)
			}
		}

		result.OnlineContacts = append(result.OnlineContacts, status)
	}

	s.logger.Debug("ProcessContactList: completed",
		"owner_uin", req.UIN,
		"total_contacts", len(req.Contacts),
		"online_count", countOnlineContacts(result.OnlineContacts),
	)

	return result, nil
}

// countOnlineContacts counts the number of online contacts in a ContactStatus slice.
func countOnlineContacts(contacts []ContactStatus) int {
	count := 0
	for _, c := range contacts {
		if c.Online {
			count++
		}
	}
	return count
}

// ProcessUserAdd processes a user add request and returns information about the target user.
// This is the service layer method for user add operations that handlers call after
// parsing user add packets (CMD_USER_ADD). It checks if the target user is online
// and returns their status, along with whether to send a "you were added" notification.
//
// The method does NOT contain any protocol-specific packet building logic.
// Handlers are responsible for:
// - Parsing protocol-specific user add packets into UserAddRequest
// - Using the returned UserAddResult to send online notifications if target is online
// - Building protocol-specific "you were added" notifications if SendYouWereAdded is true
//
// From iserverd v3_process_useradd() and v5_process_useradd() - when a user adds
// someone to their contact list, the server checks if the target is online and
// optionally sends a "you were added" notification to the target.
func (s *ICQLegacyService) ProcessUserAdd(ctx context.Context, req UserAddRequest) (*UserAddResult, error) {
	result := &UserAddResult{
		TargetOnline:     false,
		TargetStatus:     0,
		TargetVersion:    0,
		SendYouWereAdded: false,
	}

	// Validate request
	if req.FromUIN == 0 {
		s.logger.Debug("ProcessUserAdd: invalid from UIN")
		return result, nil
	}
	if req.TargetUIN == 0 {
		s.logger.Debug("ProcessUserAdd: invalid target UIN")
		return result, nil
	}

	s.logger.Debug("ProcessUserAdd: processing user add",
		"from_uin", req.FromUIN,
		"target_uin", req.TargetUIN,
	)

	// Sync to clientSideBuddyList so OSCAR's BuddyArrived/Departed
	// notifications reach this legacy user for the newly added contact.
	ownerScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.FromUIN), 10))
	contactName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.TargetUIN), 10))
	if err := s.clientSideBuddyListManager.AddBuddy(ctx, ownerScreenName, contactName); err != nil {
		s.logger.Error("ProcessUserAdd: failed to add buddy to client-side list",
			"from_uin", req.FromUIN,
			"target_uin", req.TargetUIN,
			"err", err,
		)
	}

	// Check if target user is online via legacy session manager
	if s.legacySessionManager != nil {
		legacySession := s.legacySessionManager.GetSession(req.TargetUIN)
		if legacySession != nil {
			result.TargetOnline = true
			result.TargetStatus = legacySession.GetStatus()
			// SendYouWereAdded is true for legacy clients so they know someone added them
			result.SendYouWereAdded = true

			s.logger.Debug("ProcessUserAdd: target online (legacy)",
				"target_uin", req.TargetUIN,
				"status", fmt.Sprintf("0x%08X", result.TargetStatus),
			)
			return result, nil
		}
	}

	// Check if target user is online via OSCAR session
	targetScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.TargetUIN), 10))
	oscarSession := s.sessionRetriever.RetrieveSession(targetScreenName)
	if oscarSession != nil {
		result.TargetOnline = true
		result.TargetStatus = ICQLegacyStatusOnline
		result.TargetVersion = 0 // OSCAR client, not legacy
		// For OSCAR clients, we don't send "you were added" via legacy protocol
		// OSCAR has its own buddy notification mechanism
		result.SendYouWereAdded = false

		s.logger.Debug("ProcessUserAdd: target online (OSCAR)",
			"target_uin", req.TargetUIN,
		)
		return result, nil
	}

	// Target is offline
	s.logger.Debug("ProcessUserAdd: target offline",
		"target_uin", req.TargetUIN,
	)

	return result, nil
}

// ProcessMessage handles message routing and offline storage.
// This is the service layer method for messaging that handlers call after
// parsing message packets. It determines if the target user is online and
// returns routing information, or stores the message for offline delivery.
//
// The method does NOT contain any protocol-specific packet building logic.
// Handlers are responsible for:
// - Parsing protocol-specific message packets into MessageRequest
// - Using the returned MessageResult to route messages or confirm storage
// - Building protocol-specific responses
func (s *ICQLegacyService) ProcessMessage(ctx context.Context, session *LegacySession, req MessageRequest) (*MessageResult, error) {
	result := &MessageResult{
		Delivered:     false,
		StoredOffline: false,
		TargetOnline:  false,
		TargetVersion: 0,
	}

	// Validate request
	if req.FromUIN == 0 {
		s.logger.Debug("ProcessMessage: invalid sender UIN")
		return result, nil
	}
	if req.ToUIN == 0 {
		s.logger.Debug("ProcessMessage: invalid target UIN")
		return result, nil
	}

	s.logger.Debug("ProcessMessage: processing message",
		"from", req.FromUIN,
		"to", req.ToUIN,
		"type", fmt.Sprintf("0x%04X", req.MsgType),
		"msg_len", len(req.Message),
	)

	// Check if target user is online via legacy session manager
	if s.legacySessionManager != nil {
		legacySession := s.legacySessionManager.GetSession(req.ToUIN)
		if legacySession != nil {
			// Target is online via legacy protocol
			result.TargetOnline = true
			result.Delivered = true
			// Get the protocol version from the session
			// The handler will use this to route to the correct protocol handler
			result.TargetVersion = ICQLegacyVersionV5 // Default, actual version determined by session

			s.logger.Debug("ProcessMessage: target online (legacy)",
				"to", req.ToUIN,
				"status", fmt.Sprintf("0x%08X", legacySession.GetStatus()),
			)
			return result, nil
		}
	}

	// Check if target user is online via OSCAR session
	toScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.ToUIN), 10))
	// Target is online via OSCAR protocol
	result.TargetOnline = true
	result.Delivered = true
	result.TargetVersion = 0 // OSCAR client, not legacy

	s.logger.Debug("ProcessMessage: target online (OSCAR)",
		"to", req.ToUIN,
	)

	// Send message to OSCAR client
	fromScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.FromUIN), 10))

	frame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
	}
	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelICQ,
		ScreenName: toScreenName.String(),
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN:         fromScreenName.UIN(),
					MessageType: uint8(req.MsgType),
					Message:     req.Message,
				}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			},
		},
	}
	resp, err := s.icbmService.ChannelMsgToHost(ctx, session.Instance, frame, snac)
	if err != nil {
		s.logger.Error("ProcessMessage: failed to send to OSCAR client",
			"to", req.ToUIN,
			"err", err,
		)
		// Still mark as delivered since we attempted
	}

	if resp != nil && resp.Frame.FoodGroup == wire.ICBM && resp.Frame.SubGroup == wire.ICBMErr {
		if snErr, ok := resp.Body.(wire.SNACError); ok {
			if snErr.Code == wire.ErrorCodeNotLoggedOn {
				result.Delivered = false
				result.StoredOffline = true
				result.TargetOnline = false
				s.logger.Info("ProcessMessage: message stored for offline delivery",
					"from", req.FromUIN,
					"to", req.ToUIN,
					"type", fmt.Sprintf("0x%04X", req.MsgType),
				)
			}
		}
	}

	return result, nil
}

// RegisterNewUser creates a new user account for legacy ICQ registration.
// It generates a new unique UIN, creates the user record with the provided
// profile information, and stores the password hash.
// Returns the newly assigned UIN on success.
func (s *ICQLegacyService) RegisterNewUser(ctx context.Context, nickname, firstName, lastName, email, password string) (uint32, error) {
	// Generate a new UIN
	// For now, we'll use a simple approach: find the highest existing UIN and add 1
	// In production, this should be more robust (e.g., use a sequence in the database)
	newUIN, err := s.generateNewUIN(ctx)
	if err != nil {
		return 0, fmt.Errorf("generating new UIN: %w", err)
	}

	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(newUIN), 10))

	// Create the user with the generated password
	newUser := state.User{
		IdentScreenName:   screenName,
		DisplayScreenName: state.DisplayScreenName(strconv.FormatUint(uint64(newUIN), 10)),
		IsICQ:             true,
		ICQBasicInfo: state.ICQBasicInfo{
			Nickname:     nickname,
			FirstName:    firstName,
			LastName:     lastName,
			EmailAddress: email,
		},
	}

	// Generate auth key and password hash
	newUser.AuthKey = uuid.New().String()
	newUser.StrongMD5Pass = wire.StrongMD5PasswordHash(password, newUser.AuthKey)

	// Insert the user
	if err := s.userManager.InsertUser(ctx, newUser); err != nil {
		return 0, fmt.Errorf("inserting new user: %w", err)
	}

	s.logger.Info("registered new legacy ICQ user",
		"uin", newUIN,
		"nickname", nickname,
		"email", email,
	)

	return newUIN, nil
}

// generateNewUIN generates a new unique UIN for registration
func (s *ICQLegacyService) generateNewUIN(ctx context.Context) (uint32, error) {
	// Start from a base UIN (e.g., 100000) and find the next available
	// This is a simple implementation - in production, use database sequences
	baseUIN := uint32(100000)

	for uin := baseUIN; uin < 999999999; uin++ {
		screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
		user, err := s.userManager.User(ctx, screenName)
		if err != nil {
			if errors.Is(err, state.ErrNoUser) {
				// This UIN is available
				return uin, nil
			}
			return 0, fmt.Errorf("checking UIN availability: %w", err)
		}
		if user == nil {
			// This UIN is available
			return uin, nil
		}
	}

	return 0, errors.New("no available UINs")
}

// sendToOSCARClient sends a message to an OSCAR client
func (s *ICQLegacyService) sendToOSCARClient(ctx context.Context, from, to state.IdentScreenName, msgType uint16, message string) error {
	// Strip trailing null bytes from legacy messages
	message = strings.TrimRight(message, "\x00")

	// Messages that use FE-delimited format (URLs, contacts) are sent on
	// ICBM Channel 4 with their original message type preserved.
	// OSCAR ICQ clients handle these natively on Channel 4.
	if msgType == ICQLegacyMsgURL || msgType == ICQLegacyMsgContacts {
		fromUINVal, _ := strconv.ParseUint(from.String(), 10, 32)
		var urlSenderInfo wire.TLVUserInfo
		if s.legacySessionManager != nil {
			session := s.legacySessionManager.GetSession(uint32(fromUINVal))
			if session != nil && session.Instance != nil {
				urlSenderInfo = session.Instance.Session().TLVUserInfo()
			}
		}
		if urlSenderInfo.ScreenName == "" {
			urlSenderInfo = wire.TLVUserInfo{ScreenName: from.String()}
		}
		ch4Msg := wire.ICBMCh4Message{
			UIN:         uint32(fromUINVal),
			MessageType: uint8(ICQLegacyMsgURL),
			Message:     message,
		}
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      generateMessageCookie(),
				ChannelID:   wire.ICBMChannelICQ,
				TLVUserInfo: urlSenderInfo,
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, ch4Msg),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		})
		return nil
	}

	// Auth grant/deny: send as ICBM Channel 4 (same as RespondAuthorizeToHost).
	// ICQ 2003b handles auth responses on Channel 4 correctly — it shows the
	// message and updates the pending flag. Sending as FeedbagRespondAuthorizeToClient
	// (0x13,0x1B) causes the client to remove the pending flag on deny, preventing
	// re-request authorization.
	switch msgType {
	case ICQLegacyMsgAuthGrant, ICQLegacyMsgAuthDeny:
		fromUIN, _ := strconv.ParseUint(from.String(), 10, 32)
		reasonText := strings.TrimRight(message, "\x00")

		var senderInfo wire.TLVUserInfo
		if s.legacySessionManager != nil {
			session := s.legacySessionManager.GetSession(uint32(fromUIN))
			if session != nil && session.Instance != nil {
				senderInfo = session.Instance.Session().TLVUserInfo()
			}
		}
		if senderInfo.ScreenName == "" {
			senderInfo = wire.TLVUserInfo{ScreenName: from.String()}
		}

		ch4Msg := wire.ICBMCh4Message{
			UIN:         uint32(fromUIN),
			MessageType: uint8(msgType),
			Message:     reasonText,
		}
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      generateMessageCookie(),
				ChannelID:   wire.ICBMChannelICQ,
				TLVUserInfo: senderInfo,
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, ch4Msg),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		})
		// For auth grant, also send FeedbagRespondAuthorizeToClient so the
		// OSCAR client removes the pending flag from the feedbag item.
		// For deny, only ICBM is sent — this preserves the pending flag so
		// the user can re-request authorization.
		if msgType == ICQLegacyMsgAuthGrant {
			s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRespondAuthorizeToClient,
				},
				Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
					ScreenName: from.String(),
					Accepted:   1,
				},
			})
		}
		return nil

	case ICQLegacyMsgAuthReq:
		// Send as FeedbagRequestAuthorizeToClient so OSCAR client shows auth dialog
		reasonText := ""
		parts := strings.Split(message, "\xFE")
		if len(parts) >= 6 {
			reasonText = parts[5]
		}
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRequestAuthorizeToClient,
			},
			Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
				ScreenName: from.String(),
				Reason:     reasonText,
			},
		})
		return nil

	case ICQLegacyMsgAdded:
		fromUIN, _ := strconv.ParseUint(from.String(), 10, 32)

		// Populate TLVUserInfo from the sender's OSCAR session if available,
		// otherwise build a minimal one with ICQ flags
		var senderInfo wire.TLVUserInfo
		if s.legacySessionManager != nil {
			session := s.legacySessionManager.GetSession(uint32(fromUIN))
			if session != nil && session.Instance != nil {
				senderInfo = session.Instance.Session().TLVUserInfo()
			}
		}
		if senderInfo.ScreenName == "" {
			senderInfo = wire.TLVUserInfo{ScreenName: from.String()}
		}

		ch4Msg := wire.ICBMCh4Message{
			UIN:         uint32(fromUIN),
			MessageType: uint8(msgType),
			Message:     "",
		}
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      generateMessageCookie(),
				ChannelID:   wire.ICBMChannelICQ,
				TLVUserInfo: senderInfo,
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, ch4Msg),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		})
		return nil
	}

	// Regular text messages use ICBM Channel 1
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return fmt.Errorf("creating ICBM fragments: %w", err)
	}

	// Use sender's session TLVUserInfo if available
	var senderInfo wire.TLVUserInfo
	fromUIN, _ := strconv.ParseUint(from.String(), 10, 32)
	if s.legacySessionManager != nil {
		session := s.legacySessionManager.GetSession(uint32(fromUIN))
		if session != nil && session.Instance != nil {
			senderInfo = session.Instance.Session().TLVUserInfo()
		}
	}
	if senderInfo.ScreenName == "" {
		senderInfo = wire.TLVUserInfo{ScreenName: from.String()}
	}

	icbmMsg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			Cookie:      generateMessageCookie(),
			ChannelID:   wire.ICBMChannelIM,
			TLVUserInfo: senderInfo,
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags),
				},
			},
		},
	}

	s.messageRelayer.RelayToScreenName(ctx, to, icbmMsg)
	return nil
}

// storeOfflineMessage stores a message for offline delivery
func (s *ICQLegacyService) storeOfflineMessage(ctx context.Context, from, to state.IdentScreenName, msgType uint16, message string) error {
	// Create ICBM fragment list for the message
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return fmt.Errorf("creating ICBM fragments: %w", err)
	}

	// Store the legacy message type in ICBMTLVICQBlob so it can be
	// recovered when delivering the message to a legacy client.
	// Without this, all offline messages are delivered as type 0x0001
	// (normal text), which causes auth requests and "you were added"
	// notifications to display as garbage on the receiving client.
	msgTypeBytes := make([]byte, 2)
	msgTypeBytes[0] = byte(msgType)
	msgTypeBytes[1] = byte(msgType >> 8)

	offlineMsg := state.OfflineMessage{
		Sender:    from,
		Recipient: to,
		Sent:      s.timeNow(),
		Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			Cookie:    generateMessageCookie(),
			ChannelID: wire.ICBMChannelIM,
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags),
					wire.NewTLVBE(wire.ICBMTLVICQBlob, msgTypeBytes),
				},
			},
		},
	}

	_, err = s.offlineMessageManager.SaveMessage(ctx, offlineMsg)
	if err != nil {
		return fmt.Errorf("saving offline message: %w", err)
	}

	s.logger.Debug("stored offline message",
		"from", from.String(),
		"to", to.String(),
		"msg_type", fmt.Sprintf("0x%04X", msgType),
	)

	return nil
}

// GetOfflineMessages retrieves stored offline messages for the given UIN.
// Messages are converted from the internal OSCAR ICBM format to the legacy
// LegacyOfflineMessage format suitable for delivery by protocol handlers.
func (s *ICQLegacyService) GetOfflineMessages(ctx context.Context, uin uint32) ([]LegacyOfflineMessage, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	messages, err := s.offlineMessageManager.RetrieveMessages(ctx, screenName)
	if err != nil {
		return nil, fmt.Errorf("retrieving offline messages: %w", err)
	}

	result := make([]LegacyOfflineMessage, 0, len(messages))
	for _, msg := range messages {
		legacyMsg := LegacyOfflineMessage{
			FromUIN:   msg.Sender.UIN(),
			ToUIN:     uin,
			Timestamp: msg.Sent,
		}

		// Extract message text from OSCAR format
		if payload, hasIM := msg.Message.Bytes(wire.ICBMTLVAOLIMData); hasIM {
			msgText, err := wire.UnmarshalICBMMessageText(payload)
			if err == nil {
				legacyMsg.Message = msgText
				legacyMsg.MsgType = ICQLegacyMsgText
			}
		}

		// Restore the original legacy message type if it was stored.
		// Without this, auth requests and "you were added" messages
		// are delivered as normal text (0x0001), causing the client
		// to display the raw FE-delimited fields as garbage.
		if blob, hasBlob := msg.Message.Bytes(wire.ICBMTLVICQBlob); hasBlob && len(blob) >= 2 {
			legacyMsg.MsgType = uint16(blob[0]) | uint16(blob[1])<<8
		}

		result = append(result, legacyMsg)
	}

	return result, nil
}

// AckOfflineMessages acknowledges and deletes offline messages for the given UIN.
// Called after a client has received all offline messages to clear them from storage.
func (s *ICQLegacyService) AckOfflineMessages(ctx context.Context, uin uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.offlineMessageManager.DeleteMessages(ctx, screenName)
}

// GetUserInfo retrieves basic user information as a LegacyUserSearchResult.
// It first attempts to find the user via ICQUserFinder, falling back to a
// basic user lookup if that fails. Returns minimal info if the user is not found.
func (s *ICQLegacyService) GetUserInfo(ctx context.Context, uin uint32) (*LegacyUserSearchResult, error) {
	user, err := s.userFinder.FindByUIN(ctx, uin)
	if err != nil {
		s.logger.Debug("FindByUIN failed, trying basic lookup", "uin", uin, "err", err)
		// Try basic user lookup as fallback
		screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
		basicUser, basicErr := s.userManager.User(ctx, screenName)
		if basicErr != nil {
			s.logger.Debug("basic user lookup also failed", "uin", uin, "err", basicErr)
			// Return minimal info
			return &LegacyUserSearchResult{
				UIN:      uin,
				Nickname: strconv.FormatUint(uint64(uin), 10),
			}, nil
		}
		if basicUser != nil {
			return &LegacyUserSearchResult{
				UIN:       uin,
				Nickname:  basicUser.ICQBasicInfo.Nickname,
				FirstName: basicUser.ICQBasicInfo.FirstName,
				LastName:  basicUser.ICQBasicInfo.LastName,
				Email:     basicUser.ICQBasicInfo.EmailAddress,
			}, nil
		}
		// Return minimal info
		return &LegacyUserSearchResult{
			UIN:      uin,
			Nickname: strconv.FormatUint(uint64(uin), 10),
		}, nil
	}

	return s.userToSearchResult(user), nil
}

// GetFullUserInfo retrieves the complete user record including all ICQ info fields.
// This is used by V3 info packets that need home, work, and more info fields.
// From iserverd v3_send_home_info(), v3_send_work_info(), etc.
func (s *ICQLegacyService) GetFullUserInfo(ctx context.Context, uin uint32) (*state.User, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Debug("GetFullUserInfo failed", "uin", uin, "err", err)
		return nil, err
	}
	return user, nil
}

// GetUserInfoForProtocol retrieves user info and returns it as a typed UserInfoResult.
// This is the service layer method for user info retrieval that handlers call after
// parsing info request packets. It consolidates user info retrieval from the database
// and returns a typed result struct containing all user profile fields.
//
// The method does NOT contain any protocol-specific packet building logic.
// Handlers are responsible for:
// - Parsing protocol-specific info request packets
// - Using the returned UserInfoResult to build protocol-specific response packets
func (s *ICQLegacyService) GetUserInfoForProtocol(ctx context.Context, targetUIN uint32) (*UserInfoResult, error) {
	if targetUIN == 0 {
		s.logger.Debug("GetUserInfoForProtocol: invalid target UIN")
		return nil, nil
	}

	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(targetUIN), 10))
	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		if errors.Is(err, state.ErrNoUser) {
			s.logger.Debug("GetUserInfoForProtocol: user not found", "uin", targetUIN)
			// Return minimal info for non-existent user
			return &UserInfoResult{
				UIN:      targetUIN,
				Nickname: strconv.FormatUint(uint64(targetUIN), 10),
			}, nil
		}
		s.logger.Debug("GetUserInfoForProtocol: failed to retrieve user", "uin", targetUIN, "err", err)
		return nil, fmt.Errorf("retrieving user info: %w", err)
	}

	if user == nil {
		s.logger.Debug("GetUserInfoForProtocol: user not found", "uin", targetUIN)
		// Return minimal info for non-existent user
		return &UserInfoResult{
			UIN:      targetUIN,
			Nickname: strconv.FormatUint(uint64(targetUIN), 10),
		}, nil
	}

	// Build the result from user data
	result := &UserInfoResult{
		// Basic fields
		UIN:       targetUIN,
		Nickname:  user.ICQBasicInfo.Nickname,
		FirstName: user.ICQBasicInfo.FirstName,
		LastName:  user.ICQBasicInfo.LastName,
		Email:     user.ICQBasicInfo.EmailAddress,
		Gender:    uint8(user.ICQMoreInfo.Gender),
		Age:       uint8(user.Age(s.timeNow)),

		// Extended fields - location
		City:    user.ICQBasicInfo.City,
		State:   user.ICQBasicInfo.State,
		Country: user.ICQBasicInfo.CountryCode,
		Phone:   user.ICQBasicInfo.Phone,

		// Extended fields - more info
		Homepage: user.ICQMoreInfo.HomePageAddr,
		About:    user.ICQNotes.Notes,

		// Work info
		Company:    user.ICQWorkInfo.Company,
		Department: user.ICQWorkInfo.Department,
		Position:   user.ICQWorkInfo.Position,

		// Auth required
		AuthRequired: 1,
	}

	// Use UIN as fallback nickname if not set
	if result.Nickname == "" {
		result.Nickname = strconv.FormatUint(uint64(targetUIN), 10)
	}

	// Set auth required flag
	if user.ICQPermissions.AuthRequired {
		result.AuthRequired = 0
	}

	// Check if user is online
	// First check legacy sessions
	if s.legacySessionManager != nil {
		legacySession := s.legacySessionManager.GetSession(targetUIN)
		if legacySession != nil {
			result.Online = true
			result.Status = legacySession.GetStatus()
			s.logger.Debug("GetUserInfoForProtocol: user online (legacy)",
				"uin", targetUIN,
				"status", fmt.Sprintf("0x%08X", result.Status),
			)
			return result, nil
		}
	}

	// Check OSCAR sessions
	oscarSession := s.sessionRetriever.RetrieveSession(screenName)
	if oscarSession != nil {
		result.Online = true
		result.Status = ICQLegacyStatusOnline
		s.logger.Debug("GetUserInfoForProtocol: user online (OSCAR)", "uin", targetUIN)
	}

	s.logger.Debug("GetUserInfoForProtocol: retrieved user info",
		"uin", targetUIN,
		"nickname", result.Nickname,
		"online", result.Online,
	)

	return result, nil
}

// SearchByUIN searches for a user by their UIN and returns their profile info.
// Returns nil and an error if the user is not found.
func (s *ICQLegacyService) SearchByUIN(ctx context.Context, uin uint32) (*LegacyUserSearchResult, error) {
	user, err := s.userFinder.FindByUIN(ctx, uin)
	if err != nil {
		return nil, err
	}

	return s.userToSearchResult(user), nil
}

// SearchByName searches for users by nickname, first name, last name, or email.
// If email is provided, it takes priority over name-based search.
// Returns a slice of matching users.
func (s *ICQLegacyService) SearchByName(ctx context.Context, nick, first, last, email string) ([]LegacyUserSearchResult, error) {
	var users []state.User
	var err error

	if email != "" {
		user, findErr := s.userFinder.FindByICQEmail(ctx, email)
		if findErr == nil {
			users = []state.User{user}
		}
	} else {
		users, err = s.userFinder.FindByICQName(ctx, first, last, nick)
	}

	if err != nil {
		return nil, err
	}

	results := make([]LegacyUserSearchResult, 0, len(users))
	for _, user := range users {
		results = append(results, *s.userToSearchResult(user))
	}

	return results, nil
}

// WhitePagesSearch performs a comprehensive search across multiple user profile fields.
// This is used by the V5 META_SEARCH_WHITE (0x0532) and META_SEARCH_WHITE2 (0x0533) commands.
// From iserverd v5_search_by_white() and v5_search_by_white2() in search.cpp
//
// The search supports multiple criteria including:
// - Personal info: first name, last name, nickname, email
// - Demographics: age range, gender, language
// - Location: city, state, country
// - Work: company, department, position, occupation code
// - Interests and affiliations with keywords
// - Homepage category (White2 only)
// - Online-only filter
//
// Results are limited to 40 users maximum, matching iserverd behavior.
func (s *ICQLegacyService) WhitePagesSearch(ctx context.Context, criteria WhitePagesSearchCriteria) ([]LegacyUserSearchResult, error) {
	var allResults []state.User

	// Start with basic name/email search if those criteria are provided
	// This is the primary search method available in the current infrastructure
	hasBasicCriteria := criteria.Nickname != "" || criteria.FirstName != "" ||
		criteria.LastName != "" || criteria.Email != ""

	if hasBasicCriteria {
		if criteria.Email != "" {
			// Search by email first
			user, findErr := s.userFinder.FindByICQEmail(ctx, criteria.Email)
			if findErr == nil {
				allResults = []state.User{user}
			}
		}

		// If no email results or no email provided, search by name
		if len(allResults) == 0 && (criteria.Nickname != "" || criteria.FirstName != "" || criteria.LastName != "") {
			users, findErr := s.userFinder.FindByICQName(ctx, criteria.FirstName, criteria.LastName, criteria.Nickname)
			if findErr == nil {
				allResults = users
			}
		}
	}

	// Search by interests if interest criteria provided
	if criteria.InterestIndex > 0 && criteria.InterestIndex < 60000 {
		var keywords []string
		if criteria.InterestKeywords != "" {
			keywords = []string{criteria.InterestKeywords}
		}
		users, findErr := s.userFinder.FindByICQInterests(ctx, criteria.InterestIndex, keywords)
		if findErr == nil {
			allResults = s.mergeUserResults(allResults, users)
		}
	}

	// Search by keyword if interest keywords provided without index
	if criteria.InterestKeywords != "" && criteria.InterestIndex == 0 {
		users, findErr := s.userFinder.FindByICQKeyword(ctx, criteria.InterestKeywords)
		if findErr == nil {
			allResults = s.mergeUserResults(allResults, users)
		}
	}

	// Filter results based on additional criteria
	filteredResults := s.filterWhitePagesResults(allResults, criteria)

	// Convert to search results
	results := make([]LegacyUserSearchResult, 0, len(filteredResults))
	for _, user := range filteredResults {
		result := s.userToSearchResult(user)

		// Apply online-only filter if requested
		if criteria.OnlineOnly && !result.Online {
			continue
		}

		results = append(results, *result)

		// Limit to 40 results as per iserverd behavior
		if len(results) >= 40 {
			break
		}
	}

	s.logger.Debug("white pages search completed",
		"criteria_nickname", criteria.Nickname,
		"criteria_firstname", criteria.FirstName,
		"criteria_lastname", criteria.LastName,
		"criteria_email", criteria.Email,
		"criteria_online_only", criteria.OnlineOnly,
		"total_found", len(allResults),
		"filtered_results", len(results),
	)

	return results, nil
}

// mergeUserResults merges two user slices, removing duplicates by UIN
func (s *ICQLegacyService) mergeUserResults(existing, new []state.User) []state.User {
	seen := make(map[string]bool)
	for _, u := range existing {
		seen[u.IdentScreenName.String()] = true
	}

	result := make([]state.User, len(existing))
	copy(result, existing)

	for _, u := range new {
		if !seen[u.IdentScreenName.String()] {
			result = append(result, u)
			seen[u.IdentScreenName.String()] = true
		}
	}

	return result
}

// filterWhitePagesResults filters users based on white pages search criteria
func (s *ICQLegacyService) filterWhitePagesResults(users []state.User, criteria WhitePagesSearchCriteria) []state.User {
	if len(users) == 0 {
		return users
	}

	result := make([]state.User, 0, len(users))

	for _, user := range users {
		// Filter by age range
		if criteria.MinAge > 0 && criteria.MaxAge > 0 {
			age := uint16(user.Age(s.timeNow))
			if age < criteria.MinAge || age > criteria.MaxAge {
				continue
			}
		}

		// Filter by gender (1=female, 2=male)
		if criteria.Gender > 0 && criteria.Gender < 16 {
			if uint8(user.ICQMoreInfo.Gender) != criteria.Gender {
				continue
			}
		}

		// Filter by language
		if criteria.Language > 0 && criteria.Language < 127 {
			langMatch := false
			if user.ICQMoreInfo.Lang1 == criteria.Language ||
				user.ICQMoreInfo.Lang2 == criteria.Language ||
				user.ICQMoreInfo.Lang3 == criteria.Language {
				langMatch = true
			}
			if !langMatch {
				continue
			}
		}

		// Filter by country (home country is in ICQBasicInfo)
		if criteria.Country > 0 && criteria.Country < 20000 {
			if user.ICQBasicInfo.CountryCode != criteria.Country {
				continue
			}
		}

		// Filter by city (case-insensitive partial match, home city is in ICQBasicInfo)
		if criteria.City != "" {
			if !containsIgnoreCase(user.ICQBasicInfo.City, criteria.City) {
				continue
			}
		}

		// Filter by state (case-insensitive partial match, home state is in ICQBasicInfo)
		if criteria.State != "" {
			if !containsIgnoreCase(user.ICQBasicInfo.State, criteria.State) {
				continue
			}
		}

		// Filter by company (case-insensitive partial match)
		if criteria.Company != "" {
			if !containsIgnoreCase(user.ICQWorkInfo.Company, criteria.Company) {
				continue
			}
		}

		// Filter by position (case-insensitive partial match)
		if criteria.Position != "" {
			if !containsIgnoreCase(user.ICQWorkInfo.Position, criteria.Position) {
				continue
			}
		}

		// Filter by work code/occupation
		if criteria.WorkCode > 0 && criteria.WorkCode < 127 {
			if uint8(user.ICQWorkInfo.OccupationCode) != criteria.WorkCode {
				continue
			}
		}

		result = append(result, user)
	}

	return result
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	if substr == "" {
		return true
	}
	if s == "" {
		return false
	}
	// Simple case-insensitive contains using lowercase comparison
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	return strings.Contains(sLower, substrLower)
}

// ChangeStatus updates a user's status in the service layer.
// The actual session status is managed by the session object; this method
// provides a hook for logging and any future business logic.
func (s *ICQLegacyService) ChangeStatus(ctx context.Context, uin uint32, status uint32) error {
	// Status is managed by the session, this is just for logging
	s.logger.Debug("status changed",
		"uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)
	return nil
}

// ProcessStatusChange processes a status change and returns notification targets.
// This is the service layer method for status changes that handlers call after
// parsing status change packets. It determines which users should be notified
// of the status change (users who have this user in their contact list).
//
// The method does NOT contain any protocol-specific packet building logic.
// The method does NOT directly send packets to other sessions.
// Handlers are responsible for:
// - Parsing protocol-specific status change packets into StatusChangeRequest
// - Using the returned StatusChangeResult to send notifications to each target
// - Building protocol-specific notification packets
func (s *ICQLegacyService) ProcessStatusChange(ctx context.Context, req StatusChangeRequest) (*StatusChangeResult, error) {
	result := &StatusChangeResult{
		NotifyTargets: make([]NotifyTarget, 0),
	}

	// Validate request
	if req.UIN == 0 {
		s.logger.Debug("ProcessStatusChange: invalid UIN")
		return result, nil
	}

	s.logger.Debug("ProcessStatusChange: processing status change",
		"uin", req.UIN,
		"old_status", fmt.Sprintf("0x%08X", req.OldStatus),
		"new_status", fmt.Sprintf("0x%08X", req.NewStatus),
	)

	// Get all users who have this user in their contact list
	// These are the users who should be notified of the status change
	// Use the legacy session manager's NotifyContactsOfStatus method
	if s.legacySessionManager != nil {
		// Get the session for the user whose status is changing
		session := s.legacySessionManager.GetSession(req.UIN)
		if session != nil {
			// Get all UINs that should be notified (users who have this user in their contact list)
			contactsToNotify := s.legacySessionManager.NotifyContactsOfStatus(session)
			for _, contactUIN := range contactsToNotify {
				result.NotifyTargets = append(result.NotifyTargets, NotifyTarget{
					UIN:     contactUIN,
					Version: 0, // Version will be determined by handler from session
				})
			}
		}
	}

	// Also notify OSCAR clients who have this user as a buddy
	// by broadcasting through the buddy broadcaster
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(req.UIN), 10))

	// Update the legacy session's OSCAR instance status and broadcast
	// using session.TLVUserInfo() — exactly like OSCAR's SetUserInfoFields does.
	if s.legacySessionManager != nil {
		session := s.legacySessionManager.GetSession(req.UIN)
		if session != nil && session.Instance != nil {
			oscarStatus := mapLegacyStatusToOSCAR(req.NewStatus)
			session.Instance.SetUserStatusBitmask(oscarStatus)
			if oscarStatus != wire.OServiceUserStatusAvailable {
				session.Instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
			} else {
				session.Instance.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
			}

			// Mirror OSCAR's SetUserInfoFields: if invisible, send departure;
			// otherwise send arrival with updated TLVUserInfo.
			if session.Instance.Session().Invisible() {
				if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, screenName); err != nil {
					s.logger.Debug("ProcessStatusChange: failed to broadcast departure", "err", err)
				}
			} else {
				if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, session.Instance.Session().TLVUserInfo()); err != nil {
					s.logger.Debug("ProcessStatusChange: failed to broadcast to OSCAR clients", "err", err)
				}
			}
		}
	}

	s.logger.Debug("ProcessStatusChange: completed",
		"uin", req.UIN,
		"notify_count", len(result.NotifyTargets),
	)

	return result, nil
}

// NotifyStatusChange broadcasts a status change to OSCAR clients who have
// this user as a buddy. Legacy clients are notified separately by the handler
// using ProcessStatusChange results.
func (s *ICQLegacyService) NotifyStatusChange(ctx context.Context, uin uint32, status uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	oscarStatus := mapLegacyStatusToOSCAR(status)

	// Update the OSCAR instance so session.TLVUserInfo() is correct
	if s.legacySessionManager != nil {
		session := s.legacySessionManager.GetSession(uin)
		if session != nil && session.Instance != nil {
			session.Instance.SetUserStatusBitmask(oscarStatus)
			if oscarStatus != wire.OServiceUserStatusAvailable {
				session.Instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
			} else {
				session.Instance.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
			}

			// Invisible: send departure so OSCAR clients see user as offline
			if status&ICQLegacyStatusInvisible != 0 {
				if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, screenName); err != nil {
					s.logger.Debug("NotifyStatusChange: failed to broadcast departure", "err", err)
				}
				return nil
			}

			userInfo := session.Instance.Session().TLVUserInfo()
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, userInfo); err != nil {
				s.logger.Debug("NotifyStatusChange: failed to broadcast arrival", "err", err)
			}
			return nil
		}
	}

	// Fallback if no session/instance — invisible should not broadcast arrival
	if status&ICQLegacyStatusInvisible != 0 {
		if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, screenName); err != nil {
			s.logger.Debug("NotifyStatusChange: failed to broadcast departure", "err", err)
		}
		return nil
	}

	// Build minimal user info for OSCAR clients
	userFlags := uint16(wire.OServiceUserFlagICQ | wire.OServiceUserFlagOSCARFree)
	if oscarStatus != wire.OServiceUserStatusAvailable {
		userFlags |= wire.OServiceUserFlagUnavailable
	}
	userInfo := wire.TLVUserInfo{
		ScreenName: screenName.String(),
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.OServiceUserInfoUserFlags, userFlags),
				wire.NewTLVBE(wire.OServiceUserInfoStatus, oscarStatus),
				wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(s.timeNow().Unix())),
				wire.NewTLVBE(wire.OServiceUserInfoICQDC, wire.ICQDCInfo{}),
			},
		},
	}

	if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, userInfo); err != nil {
		s.logger.Debug("NotifyStatusChange: failed to broadcast arrival", "err", err)
	}

	return nil
}

// NotifyUserOnline broadcasts a user arrival to OSCAR clients who have
// this user as a buddy. Called after legacy login completes.
func (s *ICQLegacyService) NotifyUserOnline(ctx context.Context, uin uint32, status uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// Register buddy list so OSCAR's AllRelationships can discover this legacy user.
	// This mirrors what OSCAR and TOC servers do during signon.
	if err := s.buddyListRegistry.RegisterBuddyList(ctx, screenName); err != nil {
		s.logger.Error("NotifyUserOnline: failed to register buddy list", "uin", uin, "err", err)
	}

	// Update the legacy session's OSCAR instance status bitmask so that
	// session.TLVUserInfo() reflects the correct status.
	oscarStatus := mapLegacyStatusToOSCAR(status)
	if s.legacySessionManager != nil {
		session := s.legacySessionManager.GetSession(uin)
		if session != nil && session.Instance != nil {
			session.Instance.SetUserStatusBitmask(oscarStatus)
			if oscarStatus != wire.OServiceUserStatusAvailable {
				session.Instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
			} else {
				session.Instance.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
			}

			// Invisible: don't broadcast arrival — user should appear offline
			if status&ICQLegacyStatusInvisible != 0 {
				return nil
			}

			// Use the session's TLVUserInfo — same as OSCAR's SetUserInfoFields
			userInfo := session.Instance.Session().TLVUserInfo()

			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, userInfo); err != nil {
				s.logger.Debug("NotifyUserOnline: failed to broadcast arrival", "uin", uin, "err", err)
			}
		}
	}

	return nil
}

// NotifyUserOffline broadcasts a user departure to OSCAR clients who have
// this user as a buddy. Legacy clients are notified separately by the handler.
func (s *ICQLegacyService) NotifyUserOffline(ctx context.Context, uin uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, screenName); err != nil {
		s.logger.Debug("failed to broadcast departure", "err", err)
	}

	// Unregister buddy list so OSCAR's AllRelationships no longer includes
	// this legacy user. Mirrors OSCAR/TOC signoff behavior.
	if err := s.buddyListRegistry.UnregisterBuddyList(ctx, screenName); err != nil {
		s.logger.Error("NotifyUserOffline: failed to unregister buddy list", "uin", uin, "err", err)
	}

	return nil
}

// UpdateBasicInfo updates a user's basic profile information (nickname, name, email, etc.).
// This is used by V3/V5 handlers when processing META_SET_BASIC (0x03EA) commands.
func (s *ICQLegacyService) UpdateBasicInfo(ctx context.Context, uin uint32, info state.ICQBasicInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetBasicInfo(ctx, screenName, info)
}

// UpdateWorkInfo updates a user's work information (company, department, position, etc.).
// This is used by V3/V5 handlers when processing META_SET_WORK (0x03F4) commands.
func (s *ICQLegacyService) UpdateWorkInfo(ctx context.Context, uin uint32, info state.ICQWorkInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetWorkInfo(ctx, screenName, info)
}

// UpdateMoreInfo updates a user's additional profile information (homepage, birthday, languages, etc.).
// This is used by V3/V5 handlers when processing META_SET_MORE (0x03FE) commands.
func (s *ICQLegacyService) UpdateMoreInfo(ctx context.Context, uin uint32, info state.ICQMoreInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetMoreInfo(ctx, screenName, info)
}

// UpdateInterests updates a user's interests in the database.
// Deprecated: Use SetInterests instead. This method is kept for backward compatibility.
func (s *ICQLegacyService) UpdateInterests(ctx context.Context, uin uint32, info state.ICQInterests) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetInterests(ctx, screenName, info)
}

// GetInterests retrieves the user's interests from the database.
// This is used by the V5 META_USER_FULLINFO response to return user interests.
// From iserverd v5_send_meta_interestsinfo() - returns user's interests.
//
// Parameters:
//   - uin: The UIN of the user whose interests to retrieve
//
// Returns the ICQInterests struct and nil on success, or empty struct and error on failure.
func (s *ICQLegacyService) GetInterests(ctx context.Context, uin uint32) (*state.ICQInterests, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Debug("GetInterests: failed to get user", "uin", uin, "err", err)
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		s.logger.Debug("GetInterests: user not found", "uin", uin)
		return &state.ICQInterests{}, nil
	}

	s.logger.Debug("GetInterests: retrieved interests",
		"uin", uin,
		"count", user.ICQInterests.Count,
	)

	return &user.ICQInterests, nil
}

// SetInterests saves the user's interests to the database.
// This is used by the V5 META_SET_INTERESTS (0x0410) command.
// From iserverd v5_set_interests_info() - updates user's interests.
//
// Parameters:
//   - uin: The UIN of the user whose interests to update
//   - interests: The new interests to save
//
// Returns nil on success, or an error if the update fails.
func (s *ICQLegacyService) SetInterests(ctx context.Context, uin uint32, interests state.ICQInterests) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	if err := s.userUpdater.SetInterests(ctx, screenName, interests); err != nil {
		s.logger.Error("SetInterests: failed to update interests",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating interests: %w", err)
	}

	s.logger.Debug("SetInterests: interests updated",
		"uin", uin,
		"count", interests.Count,
	)

	return nil
}

// GetAffiliations retrieves the user's affiliations from the database.
// This is used by the V5 META_USER_FULLINFO response to return user affiliations.
// From iserverd v5_send_meta_affilationsinfo() - returns user's past and current affiliations.
//
// Parameters:
//   - uin: The UIN of the user whose affiliations to retrieve
//
// Returns the ICQAffiliations struct and nil on success, or empty struct and error on failure.
func (s *ICQLegacyService) GetAffiliations(ctx context.Context, uin uint32) (*state.ICQAffiliations, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Debug("GetAffiliations: failed to get user", "uin", uin, "err", err)
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		s.logger.Debug("GetAffiliations: user not found", "uin", uin)
		return &state.ICQAffiliations{}, nil
	}

	s.logger.Debug("GetAffiliations: retrieved affiliations",
		"uin", uin,
		"past_count", user.ICQAffiliations.PastCount,
		"current_count", user.ICQAffiliations.CurrentCount,
	)

	return &user.ICQAffiliations, nil
}

// SetAffiliations saves the user's affiliations to the database.
// This is used by the V5 META_SET_AFFILIATIONS (0x041A) command.
// From iserverd v5_set_affilations_info() - updates user's past and current affiliations.
//
// Parameters:
//   - uin: The UIN of the user whose affiliations to update
//   - affiliations: The new affiliations to save
//
// Returns nil on success, or an error if the update fails.
func (s *ICQLegacyService) SetAffiliations(ctx context.Context, uin uint32, affiliations state.ICQAffiliations) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	if err := s.userUpdater.SetAffiliations(ctx, screenName, affiliations); err != nil {
		s.logger.Error("SetAffiliations: failed to update affiliations",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating affiliations: %w", err)
	}

	s.logger.Debug("SetAffiliations: affiliations updated",
		"uin", uin,
		"past_count", affiliations.PastCount,
		"current_count", affiliations.CurrentCount,
	)

	return nil
}

// UpdateAffiliations updates a user's affiliations
// Deprecated: Use SetAffiliations instead. This method is kept for backward compatibility.
func (s *ICQLegacyService) UpdateAffiliations(ctx context.Context, uin uint32, info state.ICQAffiliations) error {
	return s.SetAffiliations(ctx, uin, info)
}

// UpdatePermissions updates a user's permission settings (auth required, web aware, etc.).
// This is used by V3/V5 handlers when processing permission-related commands.
func (s *ICQLegacyService) UpdatePermissions(ctx context.Context, uin uint32, info state.ICQPermissions) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetPermissions(ctx, screenName, info)
}

// DeleteUser removes a user account from the system.
// This is used by the V5 META_USER_UNREGISTER (0x04C4) command.
// The password must match the user's current password for the deletion to succeed.
// From iserverd v5_unregister_user() in meta_user.cpp
func (s *ICQLegacyService) DeleteUser(ctx context.Context, uin uint32, password string) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// First validate the password
	valid, err := s.ValidateCredentials(ctx, uin, password)
	if err != nil {
		return fmt.Errorf("validating credentials: %w", err)
	}
	if !valid {
		return errors.New("invalid password")
	}

	// Delete the user
	if err := s.userManager.DeleteUser(ctx, screenName); err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}

	s.logger.Info("user account deleted (unregistered)",
		"uin", uin,
	)

	return nil
}

// GetNotes retrieves the user's notes from the database.
// This is used by the V3 GET_NOTES (0x05AA) command.
// From iserverd v3_process_notes() - returns user's notes.
//
// Parameters:
//   - uin: The UIN of the user whose notes to retrieve
//
// Returns the notes string and nil on success, or empty string and error on failure.
func (s *ICQLegacyService) GetNotes(ctx context.Context, uin uint32) (string, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Debug("GetNotes: failed to get user", "uin", uin, "err", err)
		return "", fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		s.logger.Debug("GetNotes: user not found", "uin", uin)
		return "", nil
	}

	s.logger.Debug("GetNotes: retrieved notes",
		"uin", uin,
		"notes_len", len(user.ICQNotes.Notes),
	)

	return user.ICQNotes.Notes, nil
}

// SetNotes saves the user's notes to the database.
// This is used by the V3 SET_NOTES (0x0596) command.
// From iserverd v3_process_setnotes() - updates user's notes.
//
// Parameters:
//   - uin: The UIN of the user whose notes to update
//   - notes: The new notes content to save
//
// Returns nil on success, or an error if the update fails.
func (s *ICQLegacyService) SetNotes(ctx context.Context, uin uint32, notes string) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	userNotes := state.ICQUserNotes{
		Notes: notes,
	}

	if err := s.userUpdater.SetUserNotes(ctx, screenName, userNotes); err != nil {
		s.logger.Error("SetNotes: failed to update notes",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating notes: %w", err)
	}

	s.logger.Debug("SetNotes: notes updated",
		"uin", uin,
		"notes_len", len(notes),
	)

	return nil
}

// SetPassword changes the user's password.
// This is used by the V3 SET_PASSWORD (0x049C) command.
// From iserverd v3_process_setpass() - updates user's password.
//
// The iserverd implementation doesn't validate the old password - it just
// updates to the new password. However, for security, we optionally validate
// the old password if provided. If oldPassword is empty, we skip validation
// (matching iserverd behavior).
//
// Parameters:
//   - uin: The UIN of the user whose password to change
//   - oldPassword: The current password (empty to skip validation)
//   - newPassword: The new password to set
//
// Returns nil on success, or an error if validation fails or update fails.
func (s *ICQLegacyService) SetPassword(ctx context.Context, uin uint32, oldPassword, newPassword string) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// If old password is provided, validate it first
	if oldPassword != "" {
		valid, err := s.ValidateCredentials(ctx, uin, oldPassword)
		if err != nil {
			s.logger.Error("SetPassword: failed to validate old password",
				"uin", uin,
				"err", err,
			)
			return fmt.Errorf("validating old password: %w", err)
		}
		if !valid {
			s.logger.Info("SetPassword: old password validation failed",
				"uin", uin,
			)
			return errors.New("invalid old password")
		}
	}

	// Update the password using AccountManager
	if err := s.accountManager.SetUserPassword(ctx, screenName, newPassword); err != nil {
		s.logger.Error("SetPassword: failed to update password",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating password: %w", err)
	}

	s.logger.Info("SetPassword: password updated successfully",
		"uin", uin,
	)

	return nil
}

// SetAuthMode sets whether authorization is required to add the user to a contact list.
// This is used by the V3 SET_AUTH (0x0514) command.
// From iserverd v3_process_setauth() - updates user's auth mode in the database
// via db_users_setauthmode().
//
// When authRequired is true, other users must request authorization before adding
// this user to their contact list. The auth mode is stored in the user's
// ICQPermissions.AuthRequired field.
//
// Parameters:
//   - uin: The UIN of the user whose auth mode to set
//   - authRequired: true if authorization is required, false otherwise
//
// Returns nil on success, or an error if the update fails.
func (s *ICQLegacyService) SetAuthMode(ctx context.Context, uin uint32, authRequired bool) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// Get current user to preserve other permission settings
	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Error("SetAuthMode: failed to get user",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		s.logger.Error("SetAuthMode: user not found",
			"uin", uin,
		)
		return errors.New("user not found")
	}

	// Update the auth mode while preserving other permission settings
	permissions := user.ICQPermissions
	permissions.AuthRequired = authRequired

	if err := s.userUpdater.SetPermissions(ctx, screenName, permissions); err != nil {
		s.logger.Error("SetAuthMode: failed to update permissions",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating permissions: %w", err)
	}

	s.logger.Debug("SetAuthMode: auth mode updated",
		"uin", uin,
		"auth_required", authRequired,
	)

	return nil
}

// GetHomepageCategory retrieves the user's homepage category from the database.
// This is used by the V5 META_USER_FULLINFO response to return user homepage category.
// From iserverd v5_send_meta_hpage_cat() - returns user's homepage category.
//
// Parameters:
//   - uin: The UIN of the user whose homepage category to retrieve
//
// Returns the ICQHomepageCategory struct and nil on success, or empty struct and error on failure.
func (s *ICQLegacyService) GetHomepageCategory(ctx context.Context, uin uint32) (*state.ICQHomepageCategory, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		s.logger.Debug("GetHomepageCategory: failed to get user", "uin", uin, "err", err)
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		s.logger.Debug("GetHomepageCategory: user not found", "uin", uin)
		return &state.ICQHomepageCategory{}, nil
	}

	s.logger.Debug("GetHomepageCategory: retrieved homepage category",
		"uin", uin,
		"enabled", user.ICQHomepageCategory.Enabled,
		"index", user.ICQHomepageCategory.Index,
	)

	return &user.ICQHomepageCategory, nil
}

// SetHomepageCategory saves the user's homepage category to the database.
// This is used by the V5 META_SET_HPCAT (0x0442) command.
// From iserverd v5_set_hpcat_info() - updates user's homepage category.
//
// Parameters:
//   - uin: The UIN of the user whose homepage category to update
//   - hpcat: The new homepage category to save
//
// Returns nil on success, or an error if the update fails.
func (s *ICQLegacyService) SetHomepageCategory(ctx context.Context, uin uint32, hpcat state.ICQHomepageCategory) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	if err := s.userUpdater.SetHomepageCategory(ctx, screenName, hpcat); err != nil {
		s.logger.Error("SetHomepageCategory: failed to update homepage category",
			"uin", uin,
			"err", err,
		)
		return fmt.Errorf("updating homepage category: %w", err)
	}

	s.logger.Debug("SetHomepageCategory: homepage category updated",
		"uin", uin,
		"enabled", hpcat.Enabled,
		"index", hpcat.Index,
		"description", hpcat.Description,
	)

	return nil
}

// userToSearchResult converts a state.User to a LegacyUserSearchResult,
// populating basic profile fields and checking online status.
func (s *ICQLegacyService) userToSearchResult(user state.User) *LegacyUserSearchResult {
	uin, _ := strconv.Atoi(user.IdentScreenName.String())

	nickname := user.ICQBasicInfo.Nickname
	// Use UIN as fallback nickname if not set
	if nickname == "" {
		nickname = user.IdentScreenName.String()
	}

	result := &LegacyUserSearchResult{
		UIN:       uint32(uin),
		Nickname:  nickname,
		FirstName: user.ICQBasicInfo.FirstName,
		LastName:  user.ICQBasicInfo.LastName,
		Email:     user.ICQBasicInfo.EmailAddress,
		Gender:    uint8(user.ICQMoreInfo.Gender),
		Age:       uint8(user.Age(s.timeNow)),
	}

	// Check if user is online
	session := s.sessionRetriever.RetrieveSession(user.IdentScreenName)
	if session != nil {
		result.Online = true
		result.Status = ICQLegacyStatusOnline
	}

	return result
}

// mapLegacyStatusToOSCAR converts a legacy ICQ status value to the equivalent
// OSCAR status flags used by the AIM/OSCAR protocol.
func mapLegacyStatusToOSCAR(legacyStatus uint32) uint32 {
	var oscarStatus uint32

	// Map base status to OSCAR combined values that ICQ 2003b expects.
	// Legacy V5 clients also send combined values:
	//   Available=0x00, FFC=0x20, Away=0x01, N/A=0x05, Occupied=0x11, DND=0x13
	switch legacyStatus & 0xFF {
	case 0x00: // Online
		oscarStatus = wire.OServiceUserStatusAvailable // 0x00
	case 0x01: // Away
		oscarStatus = wire.OServiceUserStatusAway // 0x01
	case 0x02: // DND (single bit)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusDND | wire.OServiceUserStatusBusy
	case 0x04: // N/A (single bit)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusOut
	case 0x05: // N/A (Away|Out combined from V5 client)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusOut
	case 0x10: // Occupied (single bit)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusBusy
	case 0x11: // Occupied (Away|Busy combined from V5 client)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusBusy
	case 0x13: // DND (Away|DND|Busy combined from V5 client)
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusDND | wire.OServiceUserStatusBusy
	case 0x20: // Free for Chat
		oscarStatus = wire.OServiceUserStatusChat // 0x20
	default:
		oscarStatus = wire.OServiceUserStatusAvailable
	}

	// Map flags (upper word)
	if legacyStatus&ICQLegacyStatusInvisible != 0 {
		oscarStatus |= wire.OServiceUserStatusInvisible
	}
	if legacyStatus&ICQLegacyStatusFlagWebAware != 0 {
		oscarStatus |= wire.OServiceUserStatusWebAware
	}
	if legacyStatus&ICQLegacyStatusFlagBirthday != 0 {
		oscarStatus |= wire.OServiceUserStatusBirthday
	}
	if legacyStatus&ICQLegacyStatusFlagDCAuth != 0 {
		oscarStatus |= wire.OServiceUserStatusDirectRequireAuth
	}

	return oscarStatus
}

// mapOSCARStatusToLegacy converts OSCAR status flags to the equivalent
// legacy ICQ status value.
func mapOSCARStatusToLegacy(oscarStatus uint32) uint32 {
	var legacyStatus uint32

	// Map base status. ICQ 2003b sends combined status bits:
	//   Available=0x00, FFC=0x20, Away=0x01, N/A=0x05, Occupied=0x11, DND=0x13
	statusByte := oscarStatus & 0xFF
	switch statusByte {
	case 0x00:
		legacyStatus = ICQLegacyStatusOnline
	case 0x01:
		legacyStatus = ICQLegacyStatusAway
	case 0x02:
		legacyStatus = ICQLegacyStatusDND
	case 0x04:
		legacyStatus = ICQLegacyStatusNA
	case 0x05: // Away|Out -> N/A
		legacyStatus = ICQLegacyStatusNA
	case 0x10:
		legacyStatus = ICQLegacyStatusOccupied
	case 0x11: // Away|Busy -> Occupied
		legacyStatus = ICQLegacyStatusOccupied
	case 0x13: // Away|DND|Busy -> DND
		legacyStatus = ICQLegacyStatusDND
	case 0x20:
		legacyStatus = ICQLegacyStatusFFC
	default:
		switch {
		case statusByte&0x20 != 0:
			legacyStatus = ICQLegacyStatusFFC
		case statusByte&0x02 != 0 && statusByte&0x10 != 0:
			legacyStatus = ICQLegacyStatusDND
		case statusByte&0x10 != 0:
			legacyStatus = ICQLegacyStatusOccupied
		case statusByte&0x04 != 0:
			legacyStatus = ICQLegacyStatusNA
		case statusByte&0x02 != 0:
			legacyStatus = ICQLegacyStatusDND
		case statusByte&0x01 != 0:
			legacyStatus = ICQLegacyStatusAway
		default:
			legacyStatus = ICQLegacyStatusOnline
		}
	}

	// Map flags (upper word)
	if oscarStatus&wire.OServiceUserStatusInvisible != 0 {
		legacyStatus |= ICQLegacyStatusInvisible
	}
	if oscarStatus&wire.OServiceUserStatusWebAware != 0 {
		legacyStatus |= ICQLegacyStatusFlagWebAware
	}
	if oscarStatus&wire.OServiceUserStatusBirthday != 0 {
		legacyStatus |= ICQLegacyStatusFlagBirthday
	}
	if oscarStatus&wire.OServiceUserStatusDirectRequireAuth != 0 {
		legacyStatus |= ICQLegacyStatusFlagDCAuth
	}

	return legacyStatus
}

// generateMessageCookie generates a unique message cookie for ICBM messages
// using the current nanosecond timestamp.
func generateMessageCookie() uint64 {
	return uint64(time.Now().UnixNano())
}
