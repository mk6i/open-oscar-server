package icq_legacy

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ProtocolDispatcher routes packets to the appropriate version handler
type ProtocolDispatcher struct {
	v2Handler *V2Handler
	v3Handler *V3Handler
	v4Handler *V4Handler
	v5Handler *V5Handler
	config    config.ICQLegacyConfig
	logger    *slog.Logger
}

// NewProtocolDispatcher creates a new protocol dispatcher
func NewProtocolDispatcher(
	v2Handler *V2Handler,
	v3Handler *V3Handler,
	v4Handler *V4Handler,
	v5Handler *V5Handler,
	cfg config.ICQLegacyConfig,
	logger *slog.Logger,
) *ProtocolDispatcher {
	return &ProtocolDispatcher{
		v2Handler: v2Handler,
		v3Handler: v3Handler,
		v4Handler: v4Handler,
		v5Handler: v5Handler,
		config:    cfg,
		logger:    logger,
	}
}

// Dispatch routes a packet to the appropriate handler based on protocol version
func (d *ProtocolDispatcher) Dispatch(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	version, err := wire.DetectProtocolVersion(packet)
	if err != nil {
		return fmt.Errorf("detecting protocol version: %w", err)
	}

	// Check if version is supported
	if !d.config.SupportsVersion(int(version)) {
		return fmt.Errorf("unsupported protocol version: %d", version)
	}

	d.logger.Debug("dispatching packet",
		"version", version,
		"addr", addr.String(),
		"size", len(packet),
	)

	switch version {
	case wire.ICQLegacyVersionV2:
		return d.v2Handler.Handle(session, addr, packet)
	case wire.ICQLegacyVersionV3:
		return d.v3Handler.Handle(session, addr, packet)
	case wire.ICQLegacyVersionV4:
		return d.v4Handler.Handle(session, addr, packet)
	case wire.ICQLegacyVersionV5:
		return d.v5Handler.Handle(session, addr, packet)
	default:
		return fmt.Errorf("unknown protocol version: %d", version)
	}
}

// SendUserOnline sends a user online notification to a session
// This is the central dispatcher that routes to the appropriate protocol handler
// Following iserverd's architecture in handle.cpp send_user_online()
func (d *ProtocolDispatcher) SendUserOnline(toSession *LegacySession, onlineUIN uint32, status uint32) error {
	if toSession == nil {
		return nil
	}

	d.logger.Debug("dispatching user online notification",
		"to_uin", toSession.UIN,
		"to_version", toSession.Version,
		"online_uin", onlineUIN,
		"status", fmt.Sprintf("0x%08X", status),
	)

	switch toSession.Version {
	case wire.ICQLegacyVersionV2:
		return d.v2Handler.sendUserOnline(toSession, onlineUIN, status, nil, 0)
	case wire.ICQLegacyVersionV3:
		return d.v3Handler.sendUserOnline(toSession, onlineUIN, status)
	case wire.ICQLegacyVersionV4:
		return d.v4Handler.sendUserOnline(toSession, onlineUIN, status)
	case wire.ICQLegacyVersionV5:
		return d.v5Handler.sendV5UserOnline(toSession, onlineUIN, status)
	default:
		return nil
	}
}

// SendOnlineMessage sends an online message to a session
// This is the central dispatcher that routes to the appropriate protocol handler
// Following iserverd's architecture in handle.cpp send_online_message()
func (d *ProtocolDispatcher) SendOnlineMessage(toSession *LegacySession, fromUIN uint32, msgType uint16, message string) error {
	if toSession == nil {
		return nil
	}

	d.logger.Debug("dispatching online message",
		"to_uin", toSession.UIN,
		"to_version", toSession.Version,
		"from_uin", fromUIN,
		"msg_type", fmt.Sprintf("0x%04X", msgType),
	)

	switch toSession.Version {
	case wire.ICQLegacyVersionV2:
		return d.v2Handler.sendMessage(toSession, fromUIN, msgType, message)
	case wire.ICQLegacyVersionV3:
		return d.v3Handler.sendOnlineMessage(toSession, fromUIN, msgType, message, 0)
	case wire.ICQLegacyVersionV4:
		return d.v4Handler.sendOnlineMessage(toSession, fromUIN, msgType, message, 0)
	case wire.ICQLegacyVersionV5:
		return d.v5Handler.sendOnlineMessage(toSession, fromUIN, msgType, message)
	default:
		return nil
	}
}

// SendUserOffline sends a user offline notification to a session
// This is the central dispatcher that routes to the appropriate protocol handler
// Following iserverd's architecture in handle.cpp send_user_offline()
func (d *ProtocolDispatcher) SendUserOffline(toSession *LegacySession, offlineUIN uint32) error {
	if toSession == nil {
		return nil
	}

	d.logger.Debug("dispatching user offline notification",
		"to_uin", toSession.UIN,
		"to_version", toSession.Version,
		"offline_uin", offlineUIN,
	)

	switch toSession.Version {
	case wire.ICQLegacyVersionV2:
		return d.v2Handler.sendUserOffline(toSession, offlineUIN)
	case wire.ICQLegacyVersionV3:
		return d.v3Handler.sendUserOffline(toSession, offlineUIN)
	case wire.ICQLegacyVersionV4:
		return d.v4Handler.sendUserOffline(toSession, offlineUIN)
	case wire.ICQLegacyVersionV5:
		return d.v5Handler.sendV5UserOffline(toSession, offlineUIN)
	default:
		return nil
	}
}

// SendStatusChange sends a status change notification to a session
// This is the central dispatcher that routes to the appropriate protocol handler
// Following iserverd's architecture in handle.cpp send_user_status()
// This is different from SendUserOnline - it's used when a user changes status
// while already online (e.g., from Away to Online, or Online to DND)
func (d *ProtocolDispatcher) SendStatusChange(toSession *LegacySession, changedUIN uint32, newStatus uint32) error {
	if toSession == nil {
		return nil
	}

	d.logger.Debug("dispatching status change notification",
		"to_uin", toSession.UIN,
		"to_version", toSession.Version,
		"changed_uin", changedUIN,
		"new_status", fmt.Sprintf("0x%08X", newStatus),
	)

	switch toSession.Version {
	case wire.ICQLegacyVersionV2:
		return d.v2Handler.sendStatusUpdate(toSession, changedUIN, newStatus)
	case wire.ICQLegacyVersionV3:
		return d.v3Handler.sendUserStatus(toSession, changedUIN, newStatus)
	case wire.ICQLegacyVersionV4:
		return d.v4Handler.sendUserStatus(toSession, changedUIN, newStatus)
	case wire.ICQLegacyVersionV5:
		return d.v5Handler.sendV5UserStatus(toSession, changedUIN, newStatus)
	default:
		return nil
	}
}

// PacketSender is the interface for sending packets
type PacketSender interface {
	SendPacket(addr *net.UDPAddr, packet []byte) error
	SendToSession(session *LegacySession, packet []byte) error
}

// MessageDispatcher is the interface for cross-protocol message dispatching
// This follows iserverd's architecture where a central dispatcher routes
// messages to the appropriate protocol handler based on the target's version
// From iserverd handle.cpp: send_user_online(), send_user_offline(),
// send_user_status(), send_online_message()
type MessageDispatcher interface {
	// SendUserOnline notifies a session that a user has come online
	// From iserverd send_user_online() in handle.cpp
	SendUserOnline(toSession *LegacySession, onlineUIN uint32, status uint32) error

	// SendUserOffline notifies a session that a user has gone offline
	// From iserverd send_user_offline() in handle.cpp
	SendUserOffline(toSession *LegacySession, offlineUIN uint32) error

	// SendStatusChange notifies a session that a user has changed their status
	// From iserverd send_user_status() in handle.cpp
	// This is different from SendUserOnline - it's used when a user changes
	// status while already online (e.g., Away -> Online, Online -> DND)
	SendStatusChange(toSession *LegacySession, changedUIN uint32, newStatus uint32) error

	// SendOnlineMessage sends an instant message to a session
	// From iserverd send_online_message() in handle.cpp
	SendOnlineMessage(toSession *LegacySession, fromUIN uint32, msgType uint16, message string) error
}

// BaseHandler contains common functionality shared by all protocol version handlers.
// It provides V2-format helper methods for sending packets that are used as a
// fallback by the simpler protocol versions.
type BaseHandler struct {
	sessions *LegacySessionManager
	service  LegacyService
	sender   PacketSender
	logger   *slog.Logger
}

// LegacyService is the interface for the ICQ legacy service layer.
// It defines all business logic operations that protocol handlers delegate to,
// keeping handlers thin and protocol-independent logic centralized.
type LegacyService interface {
	// ValidateCredentials checks if the given UIN and password are valid.
	// Returns true if credentials are valid, false otherwise.
	ValidateCredentials(ctx context.Context, uin uint32, password string) (bool, error)

	// AuthenticateUser validates user credentials and returns authentication result.
	// This is the service layer method for authentication that handlers call after
	// parsing login packets. It validates credentials and returns a typed result
	// struct containing success/failure and session data.
	// The method does NOT contain any protocol-specific packet building logic.
	// Handlers are responsible for building protocol-specific responses based on
	// the returned AuthResult.
	AuthenticateUser(ctx context.Context, req foodgroup.AuthRequest) (*foodgroup.AuthResult, error)

	// RegisterNewUser creates a new user account for legacy ICQ registration.
	// Returns the newly assigned UIN on success.
	RegisterNewUser(ctx context.Context, nickname, firstName, lastName, email, password string) (uint32, error)

	// SendMessage sends a message from one user to another, routing to online
	// users or storing for offline delivery.
	SendMessage(ctx context.Context, fromUIN, toUIN uint32, msgType uint16, message string) error

	// GetOfflineMessages retrieves stored offline messages for the given UIN.
	GetOfflineMessages(ctx context.Context, uin uint32) ([]foodgroup.LegacyOfflineMessage, error)

	// AckOfflineMessages acknowledges and deletes offline messages for the given UIN.
	AckOfflineMessages(ctx context.Context, uin uint32) error
	// SaveOfflineMessage stores a message for offline delivery when the target user is not online.
	// This is called by V3/V5 handlers when a message is sent to an offline user.
	// From iserverd v3_process_sysmsg() and v5_process_sysmsg() - when target is offline,
	// the message is stored in the database for later delivery.
	SaveOfflineMessage(ctx context.Context, fromUIN, toUIN uint32, msgType uint16, message string) error

	// ProcessMessage handles message routing and offline storage.
	// This is the service layer method for messaging that handlers call after
	// parsing message packets. It determines if the target user is online and
	// returns routing information, or stores the message for offline delivery.
	// The method does NOT contain any protocol-specific packet building logic.
	// Handlers are responsible for building protocol-specific responses based on
	// the returned MessageResult.
	ProcessMessage(ctx context.Context, req foodgroup.MessageRequest) (*foodgroup.MessageResult, error)

	// ProcessContactList processes a contact list and returns online status for each contact.
	// This is the service layer method for contact list processing that handlers call after
	// parsing contact list packets. It checks the online status of each contact and returns
	// a ContactListResult containing the status of each contact.
	// The method does NOT contain any protocol-specific packet building logic.
	// Handlers are responsible for building protocol-specific responses based on
	// the returned ContactListResult.
	ProcessContactList(ctx context.Context, req foodgroup.ContactListRequest) (*foodgroup.ContactListResult, error)

	// ProcessUserAdd processes a user add request and returns information about the target user.
	// This is the service layer method for user add operations that handlers call after
	// parsing user add packets (CMD_USER_ADD). It checks if the target user is online
	// and returns their status, along with whether to send a "you were added" notification.
	// The method does NOT contain any protocol-specific packet building logic.
	// Handlers are responsible for building protocol-specific responses based on
	// the returned UserAddResult.
	ProcessUserAdd(ctx context.Context, req foodgroup.UserAddRequest) (*foodgroup.UserAddResult, error)

	// ProcessStatusChange processes a status change and returns notification targets.
	// This is the service layer method for status changes that handlers call after
	// parsing status change packets. It determines which users should be notified
	// of the status change (users who have this user in their contact list).
	// The method does NOT contain any protocol-specific packet building logic.
	// The method does NOT directly send packets to other sessions.
	// Handlers are responsible for building protocol-specific responses based on
	// the returned StatusChangeResult.
	ProcessStatusChange(ctx context.Context, req foodgroup.StatusChangeRequest) (*foodgroup.StatusChangeResult, error)

	// GetUserInfo retrieves basic user information as a LegacyUserSearchResult.
	GetUserInfo(ctx context.Context, uin uint32) (*foodgroup.LegacyUserSearchResult, error)
	// GetFullUserInfo returns the complete user record including all ICQ info fields.
	// This is used by V3 info packets that need home, work, and more info fields.
	// From iserverd v3_send_home_info(), v3_send_work_info(), etc.
	GetFullUserInfo(ctx context.Context, uin uint32) (*state.User, error)
	// GetUserInfoForProtocol retrieves user info and returns it as a typed UserInfoResult.
	// This is the service layer method for user info retrieval that handlers call after
	// parsing info request packets. It consolidates user info retrieval from the database
	// and returns a typed result struct containing all user profile fields.
	// The method does NOT contain any protocol-specific packet building logic.
	GetUserInfoForProtocol(ctx context.Context, targetUIN uint32) (*foodgroup.UserInfoResult, error)
	// SearchByUIN searches for a user by their UIN and returns their profile info.
	SearchByUIN(ctx context.Context, uin uint32) (*foodgroup.LegacyUserSearchResult, error)

	// SearchByName searches for users by nickname, first name, last name, or email.
	SearchByName(ctx context.Context, nick, first, last, email string) ([]foodgroup.LegacyUserSearchResult, error)

	// ChangeStatus updates a user's status in the service layer.
	ChangeStatus(ctx context.Context, uin uint32, status uint32) error

	// NotifyStatusChange broadcasts a status change to OSCAR clients who have
	// this user as a buddy.
	NotifyStatusChange(ctx context.Context, uin uint32, status uint32) error

	// NotifyUserOffline broadcasts a user departure to OSCAR clients.
	NotifyUserOffline(ctx context.Context, uin uint32) error

	// User Management
	// DeleteUser removes a user account from the system.
	// This is used by the V5 META_USER_UNREGISTER (0x04C4) command.
	// The password must match the user's current password for the deletion to succeed.
	// Returns nil on success, or an error if the user doesn't exist or password is wrong.
	DeleteUser(ctx context.Context, uin uint32, password string) error

	// White Pages Search
	// WhitePagesSearch performs a comprehensive search across multiple user profile fields.
	// This is used by the V5 META_SEARCH_WHITE (0x0532) and META_SEARCH_WHITE2 (0x0533) commands.
	// From iserverd v5_search_by_white() and v5_search_by_white2() in search.cpp
	// Returns matching users up to a maximum of 40 results.
	WhitePagesSearch(ctx context.Context, criteria foodgroup.WhitePagesSearchCriteria) ([]foodgroup.LegacyUserSearchResult, error)

	// Notes Operations
	// GetNotes retrieves the user's notes from the database.
	// This is used by the V3 GET_NOTES (0x05AA) command.
	// From iserverd v3_process_notes() - returns user's notes.
	GetNotes(ctx context.Context, uin uint32) (string, error)

	// SetNotes saves the user's notes to the database.
	// This is used by the V3 SET_NOTES (0x0596) command.
	// From iserverd v3_process_setnotes() - updates user's notes.
	SetNotes(ctx context.Context, uin uint32, notes string) error

	// Password Operations
	// SetPassword changes the user's password after validating the old password.
	// This is used by the V3 SET_PASSWORD (0x049C) command.
	// From iserverd v3_process_setpass() - updates user's password.
	// Note: The iserverd implementation doesn't validate old password, but we add
	// this validation for security. The oldPassword parameter can be empty to skip
	// validation (matching iserverd behavior).
	SetPassword(ctx context.Context, uin uint32, oldPassword, newPassword string) error

	// Auth Mode Operations
	// SetAuthMode sets whether authorization is required to add the user to a contact list.
	// This is used by the V3 SET_AUTH (0x0514) command.
	// From iserverd v3_process_setauth() - updates user's auth mode.
	// When authRequired is true, other users must request authorization before adding
	// this user to their contact list.
	SetAuthMode(ctx context.Context, uin uint32, authRequired bool) error

	// Interests Operations
	// GetInterests retrieves the user's interests from the database.
	// This is used by the V5 META_USER_FULLINFO response to return user interests.
	// From iserverd v5_send_meta_interestsinfo() - returns user's interests.
	GetInterests(ctx context.Context, uin uint32) (*state.ICQInterests, error)

	// SetInterests saves the user's interests to the database.
	// This is used by the V5 META_SET_INTERESTS (0x0410) command.
	// From iserverd v5_set_interests_info() - updates user's interests.
	SetInterests(ctx context.Context, uin uint32, interests state.ICQInterests) error

	// Affiliations Operations
	// GetAffiliations retrieves the user's affiliations from the database.
	// This is used by the V5 META_USER_FULLINFO response to return user affiliations.
	// From iserverd v5_send_meta_affilationsinfo() - returns user's past and current affiliations.
	GetAffiliations(ctx context.Context, uin uint32) (*state.ICQAffiliations, error)

	// SetAffiliations saves the user's affiliations to the database.
	// This is used by the V5 META_SET_AFFILIATIONS (0x041A) command.
	// From iserverd v5_set_affilations_info() - updates user's past and current affiliations.
	SetAffiliations(ctx context.Context, uin uint32, affiliations state.ICQAffiliations) error

	// Homepage Category Operations
	// GetHomepageCategory retrieves the user's homepage category from the database.
	// This is used by the V5 META_USER_FULLINFO response to return user homepage category.
	// From iserverd v5_send_meta_hpage_cat() - returns user's homepage category.
	GetHomepageCategory(ctx context.Context, uin uint32) (*state.ICQHomepageCategory, error)

	// SetHomepageCategory saves the user's homepage category to the database.
	// This is used by the V5 META_SET_HPCAT (0x0442) command.
	// From iserverd v5_set_hpcat_info() - updates user's homepage category.
	SetHomepageCategory(ctx context.Context, uin uint32, hpcat state.ICQHomepageCategory) error
}

// sendAck sends an acknowledgment packet to the session using V2 packet format.
func (h *BaseHandler) sendAck(session *LegacySession, seqNum uint16) error {
	pkt := wire.BuildV2Ack(seqNum)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendLoginReply sends a login success response
func (h *BaseHandler) sendLoginReply(session *LegacySession, clientSeqNum uint16) error {
	var clientIP net.IP
	if session.Addr != nil {
		clientIP = session.Addr.IP
	}
	// Use server's own sequence number for packet header
	// Echo client's login sequence in the data payload
	serverSeq := session.NextServerSeqNum()
	pkt := wire.BuildV2LoginReply(serverSeq, clientSeqNum, session.UIN, clientIP)
	pkt.Version = session.Version

	rawPkt := wire.MarshalV2ServerPacket(pkt)
	h.logger.Debug("sending V2 login reply",
		"uin", session.UIN,
		"server_seq", serverSeq,
		"client_seq", clientSeqNum,
		"command", fmt.Sprintf("0x%04X", pkt.Command),
		"data_len", len(pkt.Data),
		"raw_hex", fmt.Sprintf("%X", rawPkt),
	)

	return h.sender.SendToSession(session, rawPkt)
}

// sendBadPassword sends a bad password response
func (h *BaseHandler) sendBadPassword(addr *net.UDPAddr, seqNum uint16, version uint16) error {
	pkt := wire.BuildV2BadPassword(seqNum)
	pkt.Version = version
	return h.sender.SendPacket(addr, wire.MarshalV2ServerPacket(pkt))
}

// sendUserOnline sends a user online notification
func (h *BaseHandler) sendUserOnline(session *LegacySession, uin uint32, status uint32, ip net.IP, port uint16) error {
	pkt := wire.BuildV2UserOnline(session.NextServerSeqNum(), uin, status, ip, port)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendUserOffline sends a user offline notification
func (h *BaseHandler) sendUserOffline(session *LegacySession, uin uint32) error {
	pkt := wire.BuildV2UserOffline(session.NextServerSeqNum(), uin)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendStatusUpdate sends a status update notification
func (h *BaseHandler) sendStatusUpdate(session *LegacySession, uin uint32, status uint32) error {
	pkt := wire.BuildV2StatusUpdate(session.NextServerSeqNum(), uin, status)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendContactListDone sends a contact list processed response
func (h *BaseHandler) sendContactListDone(session *LegacySession, seqNum uint16) error {
	pkt := wire.BuildV2ContactListDone(seqNum)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendMessage sends a message to a session
func (h *BaseHandler) sendMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string) error {
	pkt := wire.BuildV2Message(session.NextServerSeqNum(), fromUIN, msgType, message)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// sendSearchResult sends a search result
func (h *BaseHandler) sendSearchResult(session *LegacySession, user *foodgroup.LegacyUserSearchResult, isLast bool) error {
	info := &wire.LegacyUserInfo{
		UIN:       user.UIN,
		Nickname:  truncateField(user.Nickname, 20, h.logger, "nickname", user.UIN),
		FirstName: truncateField(user.FirstName, 64, h.logger, "first_name", user.UIN),
		LastName:  truncateField(user.LastName, 64, h.logger, "last_name", user.UIN),
		Email:     truncateField(user.Email, 64, h.logger, "email", user.UIN),
		Auth:      user.AuthRequired,
	}
	pkt := wire.BuildV2SearchResult(session.NextServerSeqNum(), info, isLast)
	pkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}
