package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PresenceHandler handles Web AIM API presence-related endpoints.
type PresenceHandler struct {
	SessionManager   *state.WebAPISessionManager
	SessionRetriever SessionRetriever
	FeedbagService   FeedbagService
	BuddyBroadcaster BuddyBroadcaster
	ProfileManager   ProfileManager
	LocateService    LocateService
	Logger           *slog.Logger
}

// LocateService issues OSCAR locate user-info queries. A single query performs
// the blocking relationship check, the online/offline session lookup, and
// returns the user's presence info plus optional profile and away-message data.
type LocateService interface {
	UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error)
}

// BuddyBroadcaster broadcasts buddy presence updates
type BuddyBroadcaster interface {
	BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error
	BroadcastBuddyDeparted(ctx context.Context, screenName state.IdentScreenName) error
}

// maxPresenceTargets caps how many screen names a single presence/get request
// may query in target-list ("t=") mode.
const maxPresenceTargets = 10

// ProfileManager manages user profiles (uses types.ProfileManager)
type ProfileManager interface {
	SetProfile(ctx context.Context, screenName state.IdentScreenName, profile state.UserProfile) error
	Profile(ctx context.Context, screenName state.IdentScreenName) (state.UserProfile, error)
}

// PresenceData contains presence information.
type PresenceData struct {
	Groups []BuddyGroupInfo    `json:"groups,omitempty" xml:"groups>group,omitempty"`
	Users  []BuddyPresenceInfo `json:"users,omitempty" xml:"users>user,omitempty"`
}

// BuddyGroupInfo represents a buddy group with its members.
type BuddyGroupInfo struct {
	Name    string              `json:"name" xml:"name"`
	Buddies []BuddyPresenceInfo `json:"buddies" xml:"buddies>buddy"`
}

// BuddyPresenceInfo represents presence information for a buddy.
type BuddyPresenceInfo struct {
	AimID      string `json:"aimId" xml:"aimId"`
	State      string `json:"state" xml:"state"` // "online", "offline", "away", "idle"
	StatusMsg  string `json:"statusMsg,omitempty" xml:"statusMsg,omitempty"`
	AwayMsg    string `json:"awayMsg,omitempty" xml:"awayMsg,omitempty"`
	ProfileMsg string `json:"profileMsg,omitempty" xml:"profileMsg,omitempty"`
	IdleTime   int    `json:"idleTime,omitempty" xml:"idleTime,omitempty"`
	OnlineTime int64  `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"`
	UserType   string `json:"userType" xml:"userType"` // "aim", "icq", "admin"
}

// GetPresence handles GET /presence/get requests.
func (h *PresenceHandler) GetPresence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		switch err {
		case state.ErrNoWebAPISession:
			h.sendError(w, http.StatusNotFound, "session not found")
		case state.ErrWebAPISessionExpired:
			h.sendError(w, http.StatusGone, "session expired")
		default:
			h.sendError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Touch the session
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Check if buddy list is requested
	getBuddyList := r.URL.Query().Get("bl") == "1"
	wantProfileMsg := r.URL.Query().Get("profileMsg") == "1"

	// Get target users if specified
	targetUsers := r.URL.Query().Get("t")

	// Prepare response
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"

	// Create PresenceData struct to hold the response data
	presenceData := PresenceData{}

	if getBuddyList {
		// Retrieve buddy list from feedbag
		groups, err := h.getBuddyListGroups(ctx, session, wantProfileMsg)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to get buddy list", "err", err.Error())
			// Return empty buddy list on error instead of failing
			groups = []BuddyGroupInfo{}
		}
		presenceData.Groups = groups
	} else if targetUsers != "" {
		// Get presence for specific users
		users := strings.Split(targetUsers, ",")
		if len(users) > maxPresenceTargets {
			h.sendError(w, http.StatusBadRequest, fmt.Sprintf("too many screen names requested (max %d)", maxPresenceTargets))
			return
		}
		presenceList := make([]BuddyPresenceInfo, 0, len(users))

		for _, user := range users {
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}
			presenceList = append(presenceList, h.getUserPresence(ctx, session.OSCARSession, state.NewIdentScreenName(user), wantProfileMsg))
		}

		presenceData.Users = presenceList
	} else {
		// No specific request, return empty data
		presenceData.Groups = []BuddyGroupInfo{}
	}

	// Set the data to the response
	resp.Response.Data = presenceData

	// Send response in requested format
	SendResponse(w, r, resp, h.Logger)

	h.Logger.DebugContext(ctx, "presence retrieved",
		"aimsid", aimsid,
		"buddy_list", getBuddyList,
		"targets", targetUsers,
	)
}

// getBuddyListGroups retrieves the buddy list organized by groups.
func (h *PresenceHandler) getBuddyListGroups(ctx context.Context, session *state.WebAPISession, wantProfileMsg bool) ([]BuddyGroupInfo, error) {
	// Get feedbag items via the feedbag service
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	reply, err := h.FeedbagService.Query(ctx, session.OSCARSession, frame)
	if err != nil {
		return nil, err
	}
	body, ok := reply.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return nil, fmt.Errorf("unexpected feedbag reply body type %T", reply.Body)
	}
	items := body.Items

	// Organize items into groups
	groupMap := make(map[uint16]*BuddyGroupInfo)
	buddyToGroup := make(map[string]uint16)

	// First pass: identify groups
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdGroup {
			name := item.Name
			if name == "" {
				name = "Buddies" // Default group name
			}

			groupMap[item.ItemID] = &BuddyGroupInfo{
				Name:    name,
				Buddies: []BuddyPresenceInfo{},
			}
		}
	}

	// Second pass: add buddies to groups
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy {
			// Get buddy screen name
			buddyName := item.Name
			if buddyName == "" {
				continue
			}

			// Find buddy's group
			groupID := item.GroupID

			buddyToGroup[buddyName] = groupID
		}
	}

	// If no groups exist, create a default one
	if len(groupMap) == 0 {
		groupMap[0] = &BuddyGroupInfo{
			Name:    "Buddies",
			Buddies: []BuddyPresenceInfo{},
		}
	}

	// Add buddies to their groups with presence info
	for buddyName, groupID := range buddyToGroup {
		group, exists := groupMap[groupID]
		if !exists {
			// Put in first available group if group doesn't exist
			for _, g := range groupMap {
				group = g
				break
			}
		}

		// UserInfoQuery performs the blocking check and online lookup; blocked or
		// offline buddies come back as "offline", preserving the list structure.
		presence := h.getUserPresence(ctx, session.OSCARSession, state.NewIdentScreenName(buddyName), wantProfileMsg)
		group.Buddies = append(group.Buddies, presence)
	}

	// Convert map to slice
	groups := make([]BuddyGroupInfo, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, *group)
	}

	return groups, nil
}

// getUserPresence resolves a user's presence by issuing a locate UserInfoQuery
// on behalf of the requesting OSCAR session (instance). UserInfoQuery performs
// the OSCAR blocking check and online lookup internally: blocked and offline
// users both come back as a locate error, which we surface as "offline".
func (h *PresenceHandler) getUserPresence(ctx context.Context, instance *state.SessionInstance, target state.IdentScreenName, wantProfileMsg bool) BuddyPresenceInfo {
	// Default offline presence
	presence := BuddyPresenceInfo{
		AimID:    target.String(),
		State:    "offline",
		UserType: "aim",
	}

	// Determine user type
	if strings.HasPrefix(target.String(), "admin") {
		presence.UserType = "admin"
	} else if isICQScreenName(target.String()) {
		presence.UserType = "icq"
	}

	// Web-only sessions have no OSCAR instance to query on behalf of.
	if instance == nil {
		return presence
	}

	reqType := wire.LocateTypeUnavailable // away message
	if wantProfileMsg {
		reqType |= wire.LocateTypeSig // profile text
	}

	reply, err := h.LocateService.UserInfoQuery(ctx, instance, wire.SNACFrame{},
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: uint16(reqType), ScreenName: target.String()})
	if err != nil {
		h.Logger.WarnContext(ctx, "failed to query user info", "screenName", target.String(), "error", err)
		return presence
	}

	info, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		// Locate error => user is blocked or offline.
		return presence
	}

	presence.State = "online"

	if tod, ok := info.Uint32BE(wire.OServiceUserInfoSignonTOD); ok {
		presence.OnlineTime = int64(tod)
	}

	if info.IsAway() {
		presence.State = "away"
	} else if status, ok := info.Uint32BE(wire.OServiceUserInfoStatus); ok && status&wire.OServiceUserStatusDND != 0 {
		presence.State = "dnd"
	}

	if idle, ok := info.Uint16BE(wire.OServiceUserInfoIdleTime); ok && idle > 0 {
		presence.State = "idle"
		presence.IdleTime = int(idle)
	}

	if msg, ok := info.LocateInfo.String(wire.LocateTLVTagsInfoUnavailableData); ok {
		presence.AwayMsg = msg
	}

	if wantProfileMsg {
		if prof, ok := info.LocateInfo.String(wire.LocateTLVTagsInfoSigData); ok {
			presence.ProfileMsg = prof
		}
	}

	return presence
}

// isICQScreenName checks if a screen name is an ICQ number.
func isICQScreenName(screenName string) bool {
	if len(screenName) == 0 {
		return false
	}
	for _, r := range screenName {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sendError is a convenience method that wraps the common SendError function.
func (h *PresenceHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	SendError(w, statusCode, message)
}

// SetState handles GET /presence/setState requests to update user's presence state.
func (h *PresenceHandler) SetState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.sendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		stateParam = r.URL.Query().Get("view")
	}
	awayMsg := r.URL.Query().Get("awayMsg")
	if awayMsg == "" {
		awayMsg = r.URL.Query().Get("away")
	}

	// Get OSCAR session if available
	oscarSession := session.OSCARSession
	if oscarSession == nil {
		// For web-only sessions, we'll need to track state in the WebAPI session
		// For now, just store in event data
		h.Logger.WarnContext(ctx, "no OSCAR session for presence update", "aimsid", aimsid)

		// Still send success response
		response := BaseResponse{}
		response.Response.StatusCode = 200
		response.Response.StatusText = "OK"
		SendResponse(w, r, response, h.Logger)
		return
	}

	// Map web state to OSCAR status bits
	var statusBitmask uint32
	switch stateParam {
	case "online":
		statusBitmask = 0x0000 // Clear all status bits
		oscarSession.SetAwayMessage("")
		oscarSession.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
	case "away":
		statusBitmask = wire.OServiceUserStatusAway
		oscarSession.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
		if awayMsg != "" {
			oscarSession.SetAwayMessage(awayMsg)
		}
	case "invisible":
		statusBitmask = wire.OServiceUserStatusInvisible
	case "dnd":
		statusBitmask = wire.OServiceUserStatusDND
	default:
		h.sendError(w, http.StatusBadRequest, "invalid state parameter")
		return
	}

	// Update OSCAR session status
	oscarSession.SetUserStatusBitmask(statusBitmask)

	// Broadcast presence update
	if statusBitmask&wire.OServiceUserStatusInvisible != 0 {
		// User going invisible - broadcast departure
		if err := h.BuddyBroadcaster.BroadcastBuddyDeparted(ctx, oscarSession.IdentScreenName()); err != nil {
			h.Logger.ErrorContext(ctx, "failed to broadcast buddy departed", "err", err.Error())
		}
	} else {
		// User visible - broadcast arrival/update
		if err := h.BuddyBroadcaster.BroadcastBuddyArrived(ctx, oscarSession.IdentScreenName(), oscarSession.Session().TLVUserInfo()); err != nil {
			h.Logger.ErrorContext(ctx, "failed to broadcast buddy arrived", "err", err.Error())
		}
	}

	// Queue presence event for other WebAPI sessions watching this user
	h.broadcastPresenceEvent(session.ScreenName.IdentScreenName(), stateParam, awayMsg, "")

	h.Logger.InfoContext(ctx, "presence state updated",
		"screenName", session.ScreenName.String(),
		"state", stateParam,
		"hasAwayMsg", awayMsg != "",
	)

	// Send success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = map[string]interface{}{
		"aimId":      session.ScreenName.String(),
		"displayId":  session.ScreenName.String(),
		"state":      stateParam,
		"awayMsg":    awayMsg,
		"statusMsg":  "",
		"userType":   "aim",
		"onlineTime": time.Now().Unix(),
	}
	SendResponse(w, r, response, h.Logger)
}

// SetStatus handles GET /presence/setStatus requests to update user's status message.
func (h *PresenceHandler) SetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.sendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Get the status message
	statusMsg := r.URL.Query().Get("statusMsg")
	statusCode := r.URL.Query().Get("statusCode")

	// Store status message in session (this would normally be stored in a profile/status service)
	// For now, we'll broadcast it as part of presence

	// Get OSCAR session if available
	if oscarSession := session.OSCARSession; oscarSession != nil {
		// In OSCAR, status messages are typically part of the profile
		// We'll need to extend this based on the actual implementation

		// Broadcast presence update with new status
		if err := h.BuddyBroadcaster.BroadcastBuddyArrived(ctx, oscarSession.IdentScreenName(), oscarSession.Session().TLVUserInfo()); err != nil {
			h.Logger.ErrorContext(ctx, "failed to broadcast status update", "err", err.Error())
		}
	}

	// Queue status event for other WebAPI sessions
	h.broadcastPresenceEvent(session.ScreenName.IdentScreenName(), "", "", statusMsg)

	h.Logger.InfoContext(ctx, "status message updated",
		"screenName", session.ScreenName.String(),
		"statusMsg", statusMsg,
		"statusCode", statusCode,
	)

	// Send success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	SendResponse(w, r, response, h.Logger)
}

// SetProfile handles GET /presence/setProfile requests to update user's profile.
func (h *PresenceHandler) SetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.sendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Get the profile content
	profileText := r.URL.Query().Get("profile")

	// Limit profile size (4KB max)
	if len(profileText) > 4096 {
		h.sendError(w, http.StatusBadRequest, "profile too large (max 4KB)")
		return
	}

	// Save profile using ProfileManager
	profile := state.UserProfile{
		ProfileText: profileText,
		UpdateTime:  time.Now().UTC(),
	}
	if err := h.ProfileManager.SetProfile(ctx, session.ScreenName.IdentScreenName(), profile); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set profile", "err", err.Error())
		h.sendError(w, http.StatusInternalServerError, "failed to save profile")
		return
	}

	h.Logger.InfoContext(ctx, "profile updated",
		"screenName", session.ScreenName.String(),
		"profileSize", len(profileText),
	)

	// Send success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	SendResponse(w, r, response, h.Logger)
}

// GetProfile handles GET /presence/getProfile requests to retrieve user's profile.
func (h *PresenceHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.sendError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Get target screen name (optional - defaults to self)
	targetSN := r.URL.Query().Get("sn")
	if targetSN == "" {
		targetSN = session.ScreenName.String()
	}

	// Retrieve profile using ProfileManager
	profile, err := h.ProfileManager.Profile(ctx, state.NewIdentScreenName(targetSN))
	if err != nil {
		h.Logger.WarnContext(ctx, "failed to get profile", "err", err.Error())
		// Return empty profile on error
		profile = state.UserProfile{}
	}

	// Send response
	lastUpdated := int64(0)
	if !profile.UpdateTime.IsZero() {
		lastUpdated = profile.UpdateTime.Unix()
	}
	responseData := map[string]interface{}{
		"screenName":  targetSN,
		"profile":     profile.ProfileText,
		"lastUpdated": lastUpdated,
	}

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = responseData
	SendResponse(w, r, response, h.Logger)
}

// Icon handles GET /presence/icon requests for presence icons.
func (h *PresenceHandler) Icon(w http.ResponseWriter, r *http.Request) {
	// Get parameters
	name := r.URL.Query().Get("name")
	size := r.URL.Query().Get("size")
	iconType := r.URL.Query().Get("type")

	if name == "" {
		h.sendError(w, http.StatusBadRequest, "missing name parameter")
		return
	}

	// Default values
	if size == "" {
		size = "32"
	}
	if iconType == "" {
		iconType = "aim"
	}

	// For now, redirect to a placeholder icon
	// In production, this would redirect to actual icon storage/CDN
	var iconURL string

	// If it's an email lookup, extract username
	if strings.Contains(name, "@") {
		parts := strings.Split(name, "@")
		if len(parts) > 0 {
			name = parts[0]
		}
	}

	// Check if user is online and get their state
	screenName := state.NewIdentScreenName(name)
	if session := h.SessionRetriever.RetrieveSession(screenName); session != nil {
		if session.Away() {
			iconURL = "/static/icons/away_" + iconType + "_" + size + ".png"
		} else if session.Idle() {
			iconURL = "/static/icons/idle_" + iconType + "_" + size + ".png"
		} else {
			iconURL = "/static/icons/online_" + iconType + "_" + size + ".png"
		}
	} else {
		iconURL = "/static/icons/offline_" + iconType + "_" + size + ".png"
	}

	// Redirect to icon URL
	http.Redirect(w, r, iconURL, http.StatusFound)
}

// broadcastPresenceEvent sends presence updates to all WebAPI sessions watching this user
func (h *PresenceHandler) broadcastPresenceEvent(screenName state.IdentScreenName, stateStr, awayMsg, statusMsg string) {
	// Get all sessions that have this user in their buddy list
	// For now, we'll broadcast to all sessions (this should be optimized)
	// Using background context as this is an async broadcast operation
	for _, sess := range h.SessionManager.GetAllSessions(context.Background()) {
		if sess.EventQueue != nil && sess.Events != nil {
			// Check if session is subscribed to presence events
			for _, event := range sess.Events {
				if event == "presence" || event == "myInfo" {
					eventData := types.PresenceEvent{
						AimID:     screenName.String(),
						State:     stateStr,
						AwayMsg:   awayMsg,
						StatusMsg: statusMsg,
					}
					sess.EventQueue.Push(types.EventTypePresence, eventData)
					break
				}
			}
		}
	}
}
