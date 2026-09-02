package webapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PresenceHandler handles Web AIM API presence-related endpoints.
type PresenceHandler struct {
	SessionManager   *SessionManager
	FeedbagService   FeedbagService
	BuddyBroadcaster BuddyBroadcaster
	LocateService    LocateService
	IconSource       BuddyIconSource
	Logger           *slog.Logger
}

const maxPresenceTargets = 32

// ProfileData is the getProfile payload.
type ProfileData struct {
	ScreenName  string `json:"screenName" xml:"screenName"`
	Profile     string `json:"profile" xml:"profile"`
	LastUpdated int64  `json:"lastUpdated" xml:"lastUpdated"`
}

// SetStateData echoes the identity fields a setState changed.
type SetStateData struct {
	AimID      string `json:"aimId" xml:"aimId"`
	DisplayID  string `json:"displayId" xml:"displayId"`
	State      string `json:"state" xml:"state"`
	AwayMsg    string `json:"awayMsg" xml:"awayMsg"`
	StatusMsg  string `json:"statusMsg" xml:"statusMsg"`
	UserType   string `json:"userType" xml:"userType"`
	OnlineTime int64  `json:"onlineTime" xml:"onlineTime"`
}

// presenceTargets returns the screen names a presence/get request asks about.
// Both spellings of the list are accepted and combined: one t carrying comma-
// separated names, and t repeated once per name.
func presenceTargets(r *http.Request) []string {
	var targets []string
	for _, value := range paramValues(r, "t") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				targets = append(targets, name)
			}
		}
	}
	return targets
}

// PresenceData contains presence information. Each query fills in one field and
// leaves the other nil.
//
// omitzero, not omitempty: a query matching nothing must still render its key as an
// empty array, since clients read data.groups and data.users strictly.
type PresenceData struct {
	Groups []BuddyGroupInfo    `json:"groups,omitzero" xml:"groups>group,omitempty"`
	Users  []BuddyPresenceInfo `json:"users,omitzero" xml:"users>user,omitempty"`
}

// BuddyGroupInfo represents a buddy group with its members.
type BuddyGroupInfo struct {
	Name    string              `json:"name" xml:"name"`
	Buddies []BuddyPresenceInfo `json:"buddies" xml:"buddies>buddy"`
}

// BuddyPresenceInfo represents presence information for a buddy.
//
// AimID is the normalized screen name the web client keys users by; DisplayID
// preserves the casing and spacing the user signed on with. The client renders
// DisplayID and falls back to AimID when it is absent.
type BuddyPresenceInfo struct {
	AimID      string `json:"aimId" xml:"aimId"`
	DisplayID  string `json:"displayId,omitempty" xml:"displayId,omitempty"`
	Friendly   string `json:"friendly,omitempty" xml:"friendly,omitempty"` // Viewer's private alias, rendered in preference to DisplayID
	State      string `json:"state" xml:"state"`                           // "online", "offline", "away", "idle"
	StatusMsg  string `json:"statusMsg,omitempty" xml:"statusMsg,omitempty"`
	AwayMsg    string `json:"awayMsg,omitempty" xml:"awayMsg,omitempty"`
	ProfileMsg string `json:"profileMsg,omitempty" xml:"profileMsg,omitempty"`
	IdleTime   int    `json:"idleTime,omitempty" xml:"idleTime,omitempty"`
	OnlineTime int64  `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"`
	UserType   string `json:"userType" xml:"userType"` // "aim", "icq", "admin"
	BuddyIcon  string `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`
	// Profile carries member-directory fields, present only under mdir=1. It must be
	// non-nil even when empty: clients treat a missing profile as "not a user".
	Profile *BuddyProfileInfo `json:"profile,omitempty" xml:"profile,omitempty"`
}

// BuddyProfileInfo is the nested "profile" object carried under mdir=1. Gender and
// birth date are absent because the directory record has nowhere to store them.
type BuddyProfileInfo struct {
	FriendlyName string             `json:"friendlyName,omitempty" xml:"friendlyName,omitempty"`
	FirstName    string             `json:"firstName,omitempty" xml:"firstName,omitempty"`
	LastName     string             `json:"lastName,omitempty" xml:"lastName,omitempty"`
	HomeAddress  []BuddyAddressInfo `json:"homeAddress,omitempty" xml:"homeAddress,omitempty"`
}

// BuddyAddressInfo is one entry of a profile's homeAddress array.
type BuddyAddressInfo struct {
	City    string `json:"city,omitempty" xml:"city,omitempty"`
	State   string `json:"state,omitempty" xml:"state,omitempty"`
	Country string `json:"country,omitempty" xml:"country,omitempty"`
}

// GetPresence handles GET /presence/get requests.
func (h *PresenceHandler) GetPresence(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := session.AimSID

	// Check if buddy list is requested
	getBuddyList := r.URL.Query().Get("bl") == "1"
	wantProfileMsg := r.URL.Query().Get("profileMsg") == "1"
	// mdir asks for member-directory fields alongside presence.
	wantDirInfo := isTrueParam(r.URL.Query().Get("mdir"))

	targetUsers := presenceTargets(r)

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
	} else if len(targetUsers) > 0 {
		// Get presence for specific users
		if len(targetUsers) > maxPresenceTargets {
			// truncate rather than reject
			h.Logger.WarnContext(ctx, "presence get: truncating oversized target list",
				"aimsid", session.AimSID,
				"requested", len(targetUsers),
				"cap", maxPresenceTargets,
			)
			targetUsers = targetUsers[:maxPresenceTargets]
		}
		presenceList := make([]BuddyPresenceInfo, 0, len(targetUsers))

		// The client's user-object merge deletes any alias it holds, so every
		// presence payload has to carry friendly for aliased buddies.
		aliases := session.Aliases(ctx)

		for _, user := range targetUsers {
			info := h.getUserPresence(ctx, session.OSCARSession, session.BaseURL, state.DisplayScreenName(user), wantProfileMsg)
			info.Friendly = aliases[info.AimID]
			if wantDirInfo {
				info.Profile = h.directoryProfile(ctx, user)
			}
			presenceList = append(presenceList, info)
		}

		presenceData.Users = presenceList
	} else {
		presenceData.Groups = []BuddyGroupInfo{}
		presenceData.Users = []BuddyPresenceInfo{}
	}

	// Send response in requested format
	SendOK(w, r, presenceData, h.Logger)

	h.Logger.DebugContext(ctx, "presence retrieved",
		"aimsid", aimsid,
		"buddy_list", getBuddyList,
		"targets", targetUsers,
	)
}

// directoryProfile reads a user's member-directory record for the mdir=1 profile
// object. It never returns nil: a user with no directory record must still appear
// as an empty profile rather than be dropped.
func (h *PresenceHandler) directoryProfile(ctx context.Context, screenName string) *BuddyProfileInfo {
	profile := &BuddyProfileInfo{}

	reply, err := h.LocateService.DirInfo(ctx, wire.SNACFrame{}, wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: screenName})
	if err != nil {
		h.Logger.ErrorContext(ctx, "presence: directory lookup failed",
			"screenName", screenName, "err", err.Error())
		return profile
	}
	body, ok := reply.Body.(wire.SNAC_0x02_0x0C_LocateGetDirReply)
	if !ok {
		return profile
	}

	profile.FirstName, _ = body.String(wire.ODirTLVFirstName)
	profile.LastName, _ = body.String(wire.ODirTLVLastName)
	profile.FriendlyName, _ = body.String(wire.ODirTLVNickName)

	city, _ := body.String(wire.ODirTLVCity)
	stateName, _ := body.String(wire.ODirTLVState)
	country, _ := body.String(wire.ODirTLVCountry)
	if city != "" || stateName != "" || country != "" {
		profile.HomeAddress = []BuddyAddressInfo{{City: city, State: stateName, Country: country}}
	}

	return profile
}

// getBuddyListGroups retrieves the buddy list organized by groups.
func (h *PresenceHandler) getBuddyListGroups(ctx context.Context, session *Session, wantProfileMsg bool) ([]BuddyGroupInfo, error) {
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

	// Organize items into groups, keyed by GroupID. Group rows store their
	// identity in GroupID (ItemID is 0 for every group), so a GroupID-keyed map
	// is the only way to associate buddies — which reference their group via
	// GroupID — with the right group.
	groupMap := make(map[uint16]*BuddyGroupInfo)

	// First pass: identify groups. Skip the root group (GroupID 0), which holds
	// the master group order rather than buddies.
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdGroup || item.GroupID == 0 {
			continue
		}
		name := item.Name
		if name == "" {
			name = "Buddies" // Default group name
		}
		groupMap[item.GroupID] = &BuddyGroupInfo{
			Name:    name,
			Buddies: []BuddyPresenceInfo{},
		}
	}

	// Second pass: add buddies to their group with presence info.
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdBuddy || item.Name == "" {
			continue
		}
		group, exists := groupMap[item.GroupID]
		if !exists {
			// Orphan buddy whose group row is missing: synthesize a default
			// group for its GroupID so the buddy is not dropped.
			group = &BuddyGroupInfo{Name: "Buddies", Buddies: []BuddyPresenceInfo{}}
			groupMap[item.GroupID] = group
		}

		// UserInfoQuery performs the blocking check and online lookup; blocked or
		// offline buddies come back as "offline", preserving the list structure.
		presence := h.getUserPresence(ctx, session.OSCARSession, session.BaseURL, state.DisplayScreenName(item.Name), wantProfileMsg)
		group.Buddies = append(group.Buddies, presence)
	}

	// If no groups exist at all, return a single default group.
	if len(groupMap) == 0 {
		groupMap[0] = &BuddyGroupInfo{
			Name:    "Buddies",
			Buddies: []BuddyPresenceInfo{},
		}
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
func (h *PresenceHandler) getUserPresence(ctx context.Context, instance *state.SessionInstance, baseURL string, target state.DisplayScreenName, wantProfileMsg bool) BuddyPresenceInfo {
	ident := target.IdentScreenName()

	// Default offline presence
	presence := BuddyPresenceInfo{
		AimID:     ident.String(),
		DisplayID: target.String(),
		State:     "offline",
		UserType:  "aim",
	}

	// Determine user type
	if strings.HasPrefix(ident.String(), "admin") {
		presence.UserType = "admin"
	} else if isICQScreenName(ident.String()) {
		presence.UserType = "icq"
	}

	// The unauthenticated icon endpoint resolves presence without a session, so
	// there may be no OSCAR instance to query on behalf of.
	if instance == nil {
		return presence
	}

	reqType := wire.LocateTypeUnavailable // away message
	if wantProfileMsg {
		reqType |= wire.LocateTypeSig // profile text
	}

	reply, err := h.LocateService.UserInfoQuery(ctx, instance, wire.SNACFrame{},
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: uint16(reqType), ScreenName: ident.String()})
	if err != nil {
		h.Logger.WarnContext(ctx, "failed to query user info", "screenName", ident.String(), "error", err)
		return presence
	}

	info, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		// Locate error => user is blocked or offline.
		return presence
	}

	presence.State = "online"

	// Publish the icon only now that locate has confirmed the user is online and
	// has not blocked the caller. Offline and blocking users return above without
	// an icon, so neither their icon nor its activity-revealing hash leaks to a
	// caller they are otherwise invisible to.
	presence.BuddyIcon = h.IconSource.PublishedURL(ctx, baseURL, ident)

	// The locate reply carries the screen name as the user formatted it, which
	// beats whatever casing the caller happened to pass in.
	if info.ScreenName != "" {
		presence.DisplayID = info.ScreenName
	}

	if tod, ok := info.Uint32BE(wire.OServiceUserInfoSignonTOD); ok {
		presence.OnlineTime = int64(tod)
	}

	if st := statusBitState(info.TLVUserInfo); st != "" {
		presence.State = st
	} else if info.IsAway() {
		presence.State = "away"
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

// SetState handles GET /presence/setState requests to update user's presence state.
func (h *PresenceHandler) SetState(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		stateParam = r.URL.Query().Get("view")
	}
	awayMsg := r.URL.Query().Get("awayMsg")
	if awayMsg == "" {
		awayMsg = r.URL.Query().Get("away")
	}

	oscarSession := session.OSCARSession

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
	case "occupied":
		// ICQ's Busy, a distinct status bit from DND.
		statusBitmask = wire.OServiceUserStatusBusy
		oscarSession.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
	default:
		SendError(w, r, http.StatusBadRequest, "invalid state parameter")
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

	// Notify the user's own client so its status indicator re-renders. The AIM
	// client updates its self-presence badge only from "myInfo" events; the
	// "presence" broadcast above drives buddy dots, not the user's own state.
	// Without this, changing to Busy/Away leaves the user still showing as
	// available in their own UI.
	h.pushMyInfo(session, stateParam, awayMsg, "")

	h.Logger.InfoContext(ctx, "presence state updated",
		"screenName", session.ScreenName.String(),
		"state", stateParam,
		"hasAwayMsg", awayMsg != "",
	)

	// Send success response
	SendOK(w, r, &SetStateData{
		AimID:      session.ScreenName.IdentScreenName().String(),
		DisplayID:  session.ScreenName.String(),
		State:      stateParam,
		AwayMsg:    awayMsg,
		StatusMsg:  "",
		UserType:   "aim",
		OnlineTime: time.Now().Unix(),
	}, h.Logger)
}

// SetStatus handles GET /presence/setStatus requests to update user's status message.
func (h *PresenceHandler) SetStatus(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	// Get the status message
	statusMsg := r.URL.Query().Get("statusMsg")
	statusCode := r.URL.Query().Get("statusCode")

	// Store status message in session (this would normally be stored in a profile/status service)
	// For now, we'll broadcast it as part of presence

	oscarSession := session.OSCARSession
	// In OSCAR, status messages are typically part of the profile
	// We'll need to extend this based on the actual implementation

	// Broadcast presence update with new status
	if err := h.BuddyBroadcaster.BroadcastBuddyArrived(ctx, oscarSession.IdentScreenName(), oscarSession.Session().TLVUserInfo()); err != nil {
		h.Logger.ErrorContext(ctx, "failed to broadcast status update", "err", err.Error())
	}

	// Notify the user's own client so its status message re-renders. Preserve the
	// current presence state so a status-only change does not flip the self badge.
	h.pushMyInfo(session, currentWebState(oscarSession), oscarSession.Session().AwayMessage(), statusMsg)

	h.Logger.InfoContext(ctx, "status message updated",
		"screenName", session.ScreenName.String(),
		"statusMsg", statusMsg,
		"statusCode", statusCode,
	)

	// Send success response
	SendOK(w, r, nil, h.Logger)
}

// SetProfile handles GET /presence/setProfile requests to update user's profile.
func (h *PresenceHandler) SetProfile(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	// Get the profile content
	profileText := r.URL.Query().Get("profile")

	// Limit profile size (4KB max)
	if len(profileText) > 4096 {
		SendError(w, r, http.StatusBadRequest, "profile too large (max 4KB)")
		return
	}

	instance := session.OSCARSession

	// Save profile via OSCAR LocateService.
	setInfo := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, profileText),
			},
		},
	}
	if err := h.LocateService.SetInfo(ctx, instance, setInfo); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set profile", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to save profile")
		return
	}

	h.Logger.InfoContext(ctx, "profile updated",
		"screenName", session.ScreenName.String(),
		"profileSize", len(profileText),
	)

	// Send success response
	SendOK(w, r, nil, h.Logger)
}

// GetProfile handles GET /presence/getProfile requests to retrieve user's profile.
func (h *PresenceHandler) GetProfile(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	// Get target screen name (optional - defaults to self)
	targetSN := r.URL.Query().Get("sn")
	if targetSN == "" {
		targetSN = session.ScreenName.String()
	}

	// Retrieve profile via OSCAR LocateService.
	var profileText string
	instance := session.OSCARSession
	reply, err := h.LocateService.UserInfoQuery(ctx, instance, wire.SNACFrame{},
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: uint16(wire.LocateTypeSig), ScreenName: targetSN})
	if err != nil {
		h.Logger.WarnContext(ctx, "failed to get profile", "err", err.Error())
	} else if info, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply); ok {
		if prof, ok := info.LocateInfo.String(wire.LocateTLVTagsInfoSigData); ok {
			profileText = prof
		}
	}

	// Send response
	responseData := &ProfileData{ScreenName: targetSN, Profile: profileText}

	SendOK(w, r, responseData, h.Logger)
}

// Icon handles GET /presence/icon requests for presence icons.
func (h *PresenceHandler) Icon(w http.ResponseWriter, r *http.Request) {
	// Get parameters
	name := r.URL.Query().Get("name")
	size := r.URL.Query().Get("size")
	iconType := r.URL.Query().Get("type")

	if name == "" {
		SendError(w, r, http.StatusBadRequest, "missing name parameter")
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

	// Resolve the target's presence via OSCAR LocateService, querying on behalf
	// of the caller's session. This endpoint is unauthenticated, so fall back to
	// the offline icon when no valid session is supplied.
	var instance *state.SessionInstance
	if aimsid := r.URL.Query().Get("aimsid"); aimsid != "" {
		if session, err := h.SessionManager.GetSession(r.Context(), aimsid); err == nil {
			instance = session.OSCARSession
		}
	}

	// This endpoint serves a presence state badge, not the user's buddy icon, so
	// it has no use for a buddy icon URL.
	switch h.getUserPresence(r.Context(), instance, "", state.DisplayScreenName(name), false).State {
	case "away":
		iconURL = "/static/icons/away_" + iconType + "_" + size + ".png"
	case "idle":
		iconURL = "/static/icons/idle_" + iconType + "_" + size + ".png"
	case "offline":
		iconURL = "/static/icons/offline_" + iconType + "_" + size + ".png"
	default:
		iconURL = "/static/icons/online_" + iconType + "_" + size + ".png"
	}

	// Redirect to icon URL
	http.Redirect(w, r, iconURL, http.StatusFound)
}

// statusBitState reports the web state named by a user's ICQ status bits, or ""
// when neither Busy nor DND is set. Callers must consult it before IsAway(): Busy
// and DND also raise the unavailable flag, so an away-first test reports every busy
// user as away.
func statusBitState(info wire.TLVUserInfo) string {
	status, ok := info.Uint32BE(wire.OServiceUserInfoStatus)
	if !ok {
		return ""
	}
	switch {
	case status&wire.OServiceUserStatusBusy != 0:
		return "occupied"
	case status&wire.OServiceUserStatusDND != 0:
		return "dnd"
	}
	return ""
}

// currentWebState maps an OSCAR session's presence flags to the web state string
// the clients expect ("online", "away", "idle", "invisible", "occupied", "dnd").
func currentWebState(instance *state.SessionInstance) string {
	sess := instance.Session()
	bitmask := instance.UserStatusBitmask()
	switch {
	case sess.Invisible():
		return "invisible"
	// Checked before Away: both set the unavailable flag, so an occupied user would
	// otherwise report back as away on the next myInfo.
	case bitmask&wire.OServiceUserStatusBusy != 0:
		return "occupied"
	case bitmask&wire.OServiceUserStatusDND != 0:
		return "dnd"
	case sess.Away():
		return "away"
	case instance.Idle():
		return "idle"
	default:
		return "online"
	}
}

// pushMyInfo queues a "myInfo" event on the user's own session so the AIM client
// re-renders its self-presence badge. The client binds its identity-badge render
// to "myInfo" events only, so state changes made via setState/setStatus are
// invisible in the user's own UI unless a myInfo event is delivered.
func (h *PresenceHandler) pushMyInfo(session *Session, webState, awayMsg, statusMsg string) {
	if !session.IsSubscribedTo("myInfo") && !session.IsSubscribedTo("presence") {
		return
	}

	// buddyIcon is omitted here (empty) so the client's merge preserves the icon it
	// already holds; a setState/setStatus does not change the icon. Icon changes
	// arrive on their own myInfo via the pump's MyInfoRefresher.
	myInfo := buildMyInfo(session.ScreenName, webState, "")
	myInfo.AwayMsg = awayMsg
	myInfo.StatusMsg = statusMsg

	session.EventQueue.Push(EventType("myInfo"), myInfo)
}
