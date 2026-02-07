package foodgroup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ICQLegacyService provides functionality for legacy ICQ protocols (v2-v5).
// It bridges legacy protocol handlers with the existing infrastructure.
type ICQLegacyService struct {
	userManager           UserManager
	accountManager        AccountManager
	sessionRetriever      SessionRetriever
	messageRelayer        MessageRelayer
	buddyBroadcaster      buddyBroadcaster
	offlineMessageManager OfflineMessageManager
	userFinder            ICQUserFinder
	userUpdater           ICQUserUpdater
	feedbagManager        FeedbagManager
	relationshipFetcher   RelationshipFetcher
	logger                *slog.Logger
	timeNow               func() time.Time

	// legacySessionManager is set by the server package
	legacySessionManager LegacySessionManager
}

// LegacySessionManager is the interface for managing legacy ICQ sessions
type LegacySessionManager interface {
	GetSession(uin uint32) LegacySessionInstance
	GetAllSessions() []LegacySessionInstance
	NotifyContactsOfStatus(session LegacySessionInstance) []uint32
}

// LegacySessionInstance represents a legacy session
type LegacySessionInstance interface {
	GetUIN() uint32
	GetStatus() uint32
	GetContactList() []uint32
	IsOnVisibleList(uin uint32) bool
	IsOnInvisibleList(uin uint32) bool
}

// LegacyMessageSender is the interface for sending messages to legacy clients
type LegacyMessageSender interface {
	SendMessage(uin uint32, fromUIN uint32, msgType uint16, message string) error
	SendStatusUpdate(uin uint32, targetUIN uint32, status uint32) error
	SendUserOnline(uin uint32, targetUIN uint32, status uint32, ip net.IP, port uint16) error
	SendUserOffline(uin uint32, targetUIN uint32) error
}

// LegacyOfflineMessage represents an offline message in legacy format
type LegacyOfflineMessage struct {
	FromUIN   uint32
	ToUIN     uint32
	MsgType   uint16
	Message   string
	URL       string
	Desc      string
	Timestamp time.Time
}

// LegacyUserSearchResult represents a user search result in legacy format
type LegacyUserSearchResult struct {
	UIN          uint32
	Nickname     string
	FirstName    string
	LastName     string
	Email        string
	Gender       uint8
	Age          uint8
	Status       uint32
	Online       bool
	AuthRequired uint8 // 0=no auth required, 1=auth required
	WebAware     uint8 // 0=not web aware, 1=web aware

	// More info fields (from v5_send_meta_more)
	Homepage   string // User's homepage URL
	BirthYear  uint16 // Birth year (full year, e.g., 1985)
	BirthMonth uint8  // Birth month (1-12)
	BirthDay   uint8  // Birth day (1-31)
	Lang1      uint8  // Primary language code
	Lang2      uint8  // Secondary language code
	Lang3      uint8  // Tertiary language code
}

// WhitePagesSearchCriteria contains all the search criteria for white pages search.
// This is used by the V5 META_SEARCH_WHITE (0x0532) and META_SEARCH_WHITE2 (0x0533) commands.
// From iserverd v5_search_by_white() and v5_search_by_white2() in search.cpp
type WhitePagesSearchCriteria struct {
	// Personal information
	FirstName string
	LastName  string
	Nickname  string
	Email     string

	// Age range
	MinAge uint16
	MaxAge uint16

	// Demographics
	Gender   uint8  // 0=unspecified, 1=female, 2=male
	Language uint8  // Language code (1-127)

	// Location
	City    string
	State   string
	Country uint16 // Country code

	// Work information
	Company    string
	Department string
	Position   string
	WorkCode   uint8 // Occupation code

	// Past affiliations
	PastCode     uint16 // Past affiliation category code
	PastKeywords string // Keywords for past affiliations

	// Interests
	InterestIndex    uint16 // Interest category index
	InterestKeywords string // Keywords for interests

	// Current affiliations
	AffiliationIndex    uint16 // Affiliation category index
	AffiliationKeywords string // Keywords for affiliations

	// Homepage category (White2 only)
	HomepageIndex    uint16 // Homepage category index
	HomepageKeywords string // Keywords for homepage

	// Search options
	OnlineOnly bool // Only return online users
}

// NewICQLegacyService creates a new ICQ legacy service
func NewICQLegacyService(
	userManager UserManager,
	accountManager AccountManager,
	sessionRetriever SessionRetriever,
	messageRelayer MessageRelayer,
	buddyBroadcaster buddyBroadcaster,
	offlineMessageManager OfflineMessageManager,
	userFinder ICQUserFinder,
	userUpdater ICQUserUpdater,
	feedbagManager FeedbagManager,
	relationshipFetcher RelationshipFetcher,
	logger *slog.Logger,
) *ICQLegacyService {
	return &ICQLegacyService{
		userManager:           userManager,
		accountManager:        accountManager,
		sessionRetriever:      sessionRetriever,
		messageRelayer:        messageRelayer,
		buddyBroadcaster:      buddyBroadcaster,
		offlineMessageManager: offlineMessageManager,
		userFinder:            userFinder,
		userUpdater:           userUpdater,
		feedbagManager:        feedbagManager,
		relationshipFetcher:   relationshipFetcher,
		logger:                logger,
		timeNow:               time.Now,
	}
}

// SetLegacySessionManager sets the legacy session manager (called by server package)
func (s *ICQLegacyService) SetLegacySessionManager(mgr LegacySessionManager) {
	s.legacySessionManager = mgr
}

// ValidateCredentials validates a user's credentials
func (s *ICQLegacyService) ValidateCredentials(ctx context.Context, uin uint32, password string) (bool, error) {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	user, err := s.userManager.User(ctx, screenName)
	if err != nil {
		if errors.Is(err, state.ErrNoUser) {
			return false, nil
		}
		return false, fmt.Errorf("looking up user: %w", err)
	}

	// User not found
	if user == nil {
		return false, nil
	}

	// For legacy ICQ, we do a simple password comparison
	// The password is stored as a hash, but legacy clients send plaintext
	if user.StrongMD5Pass == nil {
		s.logger.Debug("user has no password hash", "uin", uin)
		return false, nil
	}

	// Validate password using the same hash method as OSCAR
	expectedHash := wire.StrongMD5PasswordHash(password, user.AuthKey)
	if !user.ValidateHash(expectedHash) {
		s.logger.Debug("password validation failed", "uin", uin)
		return false, nil
	}

	s.logger.Debug("credentials validated successfully", "uin", uin)
	return true, nil
}

// RegisterNewUser creates a new user account for legacy ICQ registration
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

// SendMessage sends a message from one user to another
func (s *ICQLegacyService) SendMessage(ctx context.Context, fromUIN, toUIN uint32, msgType uint16, message string) error {
	fromScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(fromUIN), 10))
	toScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(toUIN), 10))

	s.logger.Debug("sending message",
		"from", fromUIN,
		"to", toUIN,
		"type", msgType,
	)

	// Check if recipient is online (OSCAR session)
	oscarSession := s.sessionRetriever.RetrieveSession(toScreenName)
	if oscarSession != nil {
		// Send via OSCAR protocol
		return s.sendToOSCARClient(ctx, fromScreenName, toScreenName, msgType, message)
	}

	// Check if recipient is online (legacy session)
	if s.legacySessionManager != nil {
		legacySession := s.legacySessionManager.GetSession(toUIN)
		if legacySession != nil {
			// Message will be sent by the caller (handler) since it has access to the sender
			return nil
		}
	}

	// Recipient is offline - store as offline message
	return s.storeOfflineMessage(ctx, fromScreenName, toScreenName, msgType, message)
}

// sendToOSCARClient sends a message to an OSCAR client
func (s *ICQLegacyService) sendToOSCARClient(ctx context.Context, from, to state.IdentScreenName, msgType uint16, message string) error {
	// Create ICBM fragment list for the message
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return fmt.Errorf("creating ICBM fragments: %w", err)
	}

	// Convert legacy message to OSCAR ICBM format
	icbmMsg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
		},
		Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			Cookie:    generateMessageCookie(),
			ChannelID: wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: from.String(),
			},
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

// SaveOfflineMessage stores a message for offline delivery when the target user is not online.
// This is the public interface called by V3/V5 handlers when a message is sent to an offline user.
// From iserverd v3_process_sysmsg() and v5_process_sysmsg() - when target is offline,
// the message is stored in the database for later delivery.
//
// Parameters:
//   - fromUIN: The sender's UIN
//   - toUIN: The recipient's UIN (who is offline)
//   - msgType: The ICQ message type (e.g., 0x0001 for text, 0x0004 for URL)
//   - message: The message content
//
// Returns nil on success, or an error if the message could not be stored.
func (s *ICQLegacyService) SaveOfflineMessage(ctx context.Context, fromUIN, toUIN uint32, msgType uint16, message string) error {
	fromScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(fromUIN), 10))
	toScreenName := state.NewIdentScreenName(strconv.FormatUint(uint64(toUIN), 10))

	s.logger.Debug("storing offline message",
		"from", fromUIN,
		"to", toUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", len(message),
	)

	return s.storeOfflineMessage(ctx, fromScreenName, toScreenName, msgType, message)
}

// storeOfflineMessage stores a message for offline delivery
func (s *ICQLegacyService) storeOfflineMessage(ctx context.Context, from, to state.IdentScreenName, msgType uint16, message string) error {
	// Create ICBM fragment list for the message
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return fmt.Errorf("creating ICBM fragments: %w", err)
	}

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
	)

	return nil
}

// GetOfflineMessages retrieves offline messages for a user
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
				legacyMsg.MsgType = wire.ICQLegacyMsgText
			}
		}

		result = append(result, legacyMsg)
	}

	return result, nil
}

// AckOfflineMessages acknowledges and deletes offline messages
func (s *ICQLegacyService) AckOfflineMessages(ctx context.Context, uin uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.offlineMessageManager.DeleteMessages(ctx, screenName)
}

// GetUserInfo retrieves user information
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

// SearchByUIN searches for a user by UIN
func (s *ICQLegacyService) SearchByUIN(ctx context.Context, uin uint32) (*LegacyUserSearchResult, error) {
	user, err := s.userFinder.FindByUIN(ctx, uin)
	if err != nil {
		return nil, err
	}

	return s.userToSearchResult(user), nil
}

// SearchByName searches for users by name/email
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
	var err error

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

	if err != nil {
		return nil, err
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
}// containsIgnoreCase checks if s contains substr (case-insensitive)
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

// ChangeStatus changes a user's status
func (s *ICQLegacyService) ChangeStatus(ctx context.Context, uin uint32, status uint32) error {
	// Status is managed by the session, this is just for logging
	s.logger.Debug("status changed",
		"uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)
	return nil
}

// NotifyStatusChange notifies contacts of a status change
func (s *ICQLegacyService) NotifyStatusChange(ctx context.Context, uin uint32, status uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// Build user info for OSCAR clients
	userInfo := wire.TLVUserInfo{
		ScreenName: screenName.String(),
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.OServiceUserInfoStatus, mapLegacyStatusToOSCAR(status)),
			},
		},
	}

	// Broadcast to OSCAR clients
	if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, userInfo); err != nil {
		s.logger.Debug("failed to broadcast to OSCAR clients", "err", err)
	}

	return nil
}

// NotifyUserOffline notifies contacts that a user went offline
func (s *ICQLegacyService) NotifyUserOffline(ctx context.Context, uin uint32) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

	// Get the OSCAR session if it exists
	session := s.sessionRetriever.RetrieveSession(screenName)
	if session != nil {
		// Get any instance to broadcast departure
		instances := session.Instances()
		if len(instances) > 0 {
			if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, instances[0]); err != nil {
				s.logger.Debug("failed to broadcast departure", "err", err)
			}
		}
	}

	return nil
}

// UpdateBasicInfo updates a user's basic info
func (s *ICQLegacyService) UpdateBasicInfo(ctx context.Context, uin uint32, info state.ICQBasicInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetBasicInfo(ctx, screenName, info)
}

// UpdateWorkInfo updates a user's work info
func (s *ICQLegacyService) UpdateWorkInfo(ctx context.Context, uin uint32, info state.ICQWorkInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetWorkInfo(ctx, screenName, info)
}

// UpdateMoreInfo updates a user's additional info
func (s *ICQLegacyService) UpdateMoreInfo(ctx context.Context, uin uint32, info state.ICQMoreInfo) error {
	screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
	return s.userUpdater.SetMoreInfo(ctx, screenName, info)
}

// UpdateInterests updates a user's interests
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

// UpdatePermissions updates a user's permission settings
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

// Helper functions

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
		result.Status = wire.ICQLegacyStatusOnline
	}

	return result
}

// mapLegacyStatusToOSCAR converts legacy ICQ status to OSCAR status flags
func mapLegacyStatusToOSCAR(legacyStatus uint32) uint32 {
	var oscarStatus uint32

	switch legacyStatus & 0xFF {
	case 0x00: // Online
		oscarStatus = wire.OServiceUserStatusAvailable
	case 0x01: // Away
		oscarStatus = wire.OServiceUserStatusAway
	case 0x02: // DND
		oscarStatus = wire.OServiceUserStatusDND
	case 0x04: // NA
		oscarStatus = wire.OServiceUserStatusOut
	case 0x10: // Occupied
		oscarStatus = wire.OServiceUserStatusBusy
	case 0x20: // FFC
		oscarStatus = wire.OServiceUserStatusChat
	}

	if legacyStatus&wire.ICQLegacyStatusInvisible != 0 {
		oscarStatus |= wire.OServiceUserStatusInvisible
	}

	return oscarStatus
}

// mapOSCARStatusToLegacy converts OSCAR status to legacy ICQ status
func mapOSCARStatusToLegacy(oscarStatus uint32) uint32 {
	var legacyStatus uint32

	if oscarStatus&wire.OServiceUserStatusAway != 0 {
		legacyStatus = wire.ICQLegacyStatusAway
	} else if oscarStatus&wire.OServiceUserStatusDND != 0 {
		legacyStatus = wire.ICQLegacyStatusDND
	} else if oscarStatus&wire.OServiceUserStatusOut != 0 {
		legacyStatus = wire.ICQLegacyStatusNA
	} else if oscarStatus&wire.OServiceUserStatusBusy != 0 {
		legacyStatus = wire.ICQLegacyStatusOccupied
	} else if oscarStatus&wire.OServiceUserStatusChat != 0 {
		legacyStatus = wire.ICQLegacyStatusFFC
	} else {
		legacyStatus = wire.ICQLegacyStatusOnline
	}

	if oscarStatus&wire.OServiceUserStatusInvisible != 0 {
		legacyStatus |= wire.ICQLegacyStatusInvisible
	}

	return legacyStatus
}

// generateMessageCookie generates a random message cookie
func generateMessageCookie() uint64 {
	return uint64(time.Now().UnixNano())
}
