package webapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PresenceHandler handles Web AIM API presence-related endpoints.
type PresenceHandler struct {
	SessionManager  *SessionManager
	FeedbagService  FeedbagService
	LocateService   LocateService
	OServiceService OServiceService
	IconSource      BuddyIconSource
	Logger          *slog.Logger
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
	UserType   string `json:"userType" xml:"userType"` // "aim", "icq"
	OnlineTime int64  `json:"onlineTime" xml:"onlineTime"`
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
	UserType   string `json:"userType" xml:"userType"`                   // "aim", "icq"
	Service    string `json:"service,omitempty" xml:"service,omitempty"` // Non-native network; omitted for AIM
	BuddyIcon  string `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`
	MoodIcon   string `json:"moodIcon,omitempty" xml:"moodIcon,omitempty"`
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

	getBuddyList := r.URL.Query().Get("bl") == "1"
	wantProfileMsg := r.URL.Query().Get("profileMsg") == "1"
	// mdir asks for member-directory fields alongside presence.
	wantDirInfo := isTrueParam(r.URL.Query().Get("mdir"))

	targetUsers := targetNames(r)

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
			info := h.targetPresence(ctx, session, state.DisplayScreenName(user), wantProfileMsg)
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
	items, err := session.Feedbag(ctx)
	if err != nil {
		return nil, err
	}

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

		// Served from the presence view, where blocked and offline buddies alike
		// come back as "offline". profileMsg is the exception: profile text is only
		// reachable through a locate reply.
		var presence BuddyPresenceInfo
		if wantProfileMsg {
			presence = h.getUserPresence(ctx, session.OSCARSession, session.BaseURL, state.DisplayScreenName(item.Name), true)
		} else {
			presence = h.cachedPresence(ctx, session, item.Name)
		}
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

// offlinePresenceInfo is the presence a user renders as when the session has no
// maintained record of them.
func offlinePresenceInfo(ident state.IdentScreenName, target string) BuddyPresenceInfo {
	return BuddyPresenceInfo{
		AimID:     ident.String(),
		DisplayID: target,
		State:     "offline",
		UserType:  userTypeFor(ident),
		Service:   serviceFor(ident),
	}
}

// cachedPresence renders a user's presence from the session's presence view. A
// user the view has never seen renders offline, as does one who blocks the
// caller: the broadcaster sends them a departure rather than an arrival.
//
// ProfileMsg is absent; callers that want it take the locate path. AwayMsg costs
// a locate query per unavailable buddy.
func (h *PresenceHandler) cachedPresence(ctx context.Context, session *Session, target string) BuddyPresenceInfo {
	ident := state.NewIdentScreenName(target)

	presence, ok := session.BuddyPresence(ident)
	if !ok {
		return offlinePresenceInfo(ident, target)
	}
	return h.presenceInfo(ctx, session, target, presence)
}

// presenceInfo renders a presence record the caller has already read out of the
// view. Callers that branched on a cache hit pass the record in, so an eviction
// racing them cannot turn the hit into an offline reading.
func (h *PresenceHandler) presenceInfo(ctx context.Context, session *Session, target string, presence BuddyPresence) BuddyPresenceInfo {
	ident := state.NewIdentScreenName(target)
	info := offlinePresenceInfo(ident, target)

	// A departure keeps the last display name seen, which beats the normalized
	// spelling the caller passed in.
	if presence.DisplayID != "" {
		info.DisplayID = presence.DisplayID
	}

	info.State = presence.State
	info.StatusMsg = presence.StatusMsg
	info.OnlineTime = presence.OnlineTime
	info.IdleTime = presence.IdleTime

	if !presence.Online() {
		// Offline and blocking users publish no icon, so neither their icon nor
		// its activity-revealing hash leaks to a caller they are invisible to.
		return info
	}

	if hasAwayMsg(presence.State) {
		info.AwayMsg = awayMessage(ctx, h.LocateService, session.OSCARSession, ident, h.Logger)
	}

	// The presence SNAC carried the icon hash, so no metadata lookup is needed.
	info.BuddyIcon = h.IconSource.URLForHash(session.BaseURL, ident, presence.IconHash)
	info.MoodIcon = moodIconURL(session.BaseURL, presence.State, presence.Caps)

	return info
}

// targetPresence resolves one of the users named by presence/get?t=. Unlike the
// roster, a target need not be a buddy, so a user missing from the view gets a
// locate query rather than reading as offline. profileMsg takes that path too.
func (h *PresenceHandler) targetPresence(ctx context.Context, session *Session, target state.DisplayScreenName, wantProfileMsg bool) BuddyPresenceInfo {
	if !wantProfileMsg {
		if presence, ok := session.BuddyPresence(target.IdentScreenName()); ok {
			return h.presenceInfo(ctx, session, target.String(), presence)
		}
	}
	return h.getUserPresence(ctx, session.OSCARSession, session.BaseURL, target, wantProfileMsg)
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
		UserType:  userTypeFor(ident),
		Service:   serviceFor(ident),
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

	presence.State, presence.IdleTime = buddyWebState(info.TLVUserInfo, instance.IdentScreenName().UIN() == 0)

	// An offline user publishes nothing; locate still answers for an invisible one.
	if presence.State == "offline" {
		return presence
	}

	// Offline, blocking and invisible users return before this, so neither their
	// icon nor its activity-revealing hash leaks to a caller they are hidden from.
	presence.BuddyIcon = h.IconSource.PublishedURL(ctx, baseURL, ident)

	// The locate reply carries the screen name as the user formatted it, which
	// beats whatever casing the caller happened to pass in.
	if info.ScreenName != "" {
		presence.DisplayID = info.ScreenName
	}

	if tod, ok := info.Uint32BE(wire.OServiceUserInfoSignonTOD); ok {
		presence.OnlineTime = int64(tod)
	}

	if msg, ok := info.LocateInfo.String(wire.LocateTLVTagsInfoUnavailableData); ok {
		presence.AwayMsg = msg
	}

	if wantProfileMsg {
		if prof, ok := info.LocateInfo.String(wire.LocateTLVTagsInfoSigData); ok {
			presence.ProfileMsg = prof
		}
	}

	presence.MoodIcon = moodIconURL(baseURL, presence.State, userInfoCaps(info.TLVUserInfo))
	presence.StatusMsg = userStatusMsg(info.TLVUserInfo)

	return presence
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

	// Map web state to OSCAR status bits. setAwayMsg reports whether the away
	// message needs rewriting: only going online clears it, and only an away
	// state with text replaces it, so the other states keep what is there.
	var statusBitmask uint32
	var setAwayMsg bool
	switch stateParam {
	case "online":
		statusBitmask = 0x0000 // Clear all status bits
		awayMsg = ""
		setAwayMsg = true
	case "away":
		statusBitmask = wire.OServiceUserStatusAway
		setAwayMsg = awayMsg != ""
	case "invisible":
		statusBitmask = wire.OServiceUserStatusInvisible
	case "dnd":
		statusBitmask = wire.OServiceUserStatusDND
	case "occupied":
		// ICQ's Busy, a distinct status bit from DND.
		statusBitmask = wire.OServiceUserStatusBusy
	default:
		SendError(w, r, http.StatusBadRequest, "invalid state parameter")
		return
	}

	// Set the away message first, so that the user info update the status change
	// relays back carries the new message.
	if setAwayMsg {
		setInfo := wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, awayMsg),
				},
			},
		}
		if err := h.LocateService.SetInfo(ctx, oscarSession, setInfo); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set away message", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to set state")
			return
		}
	}

	setFields := wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.OServiceUserInfoStatus, statusBitmask),
			},
		},
	}
	if err := h.OServiceService.SetUserInfoFields(ctx, oscarSession, wire.SNACFrame{}, setFields); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set user info fields", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to set state")
		return
	}

	reportedState := stateParam
	if st := statusMaskState(statusBitmask, oscarSession.IdentScreenName().UIN() == 0); st != "" {
		reportedState = st
	}

	h.Logger.InfoContext(ctx, "presence state updated",
		"screenName", session.ScreenName.String(),
		"state", stateParam,
		"hasAwayMsg", awayMsg != "",
	)

	SendOK(w, r, &SetStateData{
		AimID:      session.ScreenName.IdentScreenName().String(),
		DisplayID:  session.ScreenName.String(),
		State:      reportedState,
		AwayMsg:    awayMsg,
		StatusMsg:  sessionStatusMsg(oscarSession),
		UserType:   userTypeFor(session.ScreenName.IdentScreenName()),
		OnlineTime: time.Now().Unix(),
	}, h.Logger)
}

// SetStatus handles GET /presence/setStatus requests to update user's status message.
func (h *PresenceHandler) SetStatus(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	statusMsg := r.URL.Query().Get("statusMsg")
	statusCode := r.URL.Query().Get("statusCode")

	if r.URL.Query().Has("statusMsg") {

		var bid wire.BARTID
		if err := bid.SetStatusText(statusMsg); err != nil {
			if errors.Is(err, wire.ErrStatusTextSizeExceeded) {
				SendError(w, r, http.StatusBadRequest, err.Error())
			} else {
				h.Logger.ErrorContext(ctx, "failed to marshal status message", "err", err.Error())
				SendError(w, r, http.StatusInternalServerError, "failed to set status")
			}
			return
		}

		setFields := wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, bid),
				},
			},
		}
		if err := h.OServiceService.SetUserInfoFields(ctx, session.OSCARSession, wire.SNACFrame{}, setFields); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set user info fields", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to set status")
			return
		}
	}

	if r.URL.Query().Has("mood") {
		moodID := r.URL.Query().Get("mood")
		if moodID == "" {
			session.ClearMood()
		} else {
			m, hasMood := wire.MoodByID(moodID)
			if !hasMood {
				SendError(w, r, http.StatusBadRequest, "invalid mood ID")
				return
			}

			session.SetMood(m.Cap)
		}
		setInfo := wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, session.Caps()),
				},
			},
		}
		if err := h.LocateService.SetInfo(ctx, session.OSCARSession, setInfo); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set mood capability", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to save status")
			return
		}
	}

	h.Logger.InfoContext(ctx, "status message updated",
		"screenName", session.ScreenName.String(),
		"statusMsg", statusMsg,
		"statusCode", statusCode,
		"mood", r.URL.Query().Get("mood"),
	)

	SendOK(w, r, nil, h.Logger)
}

// SetProfile handles GET /presence/setProfile requests to update user's profile.
func (h *PresenceHandler) SetProfile(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	profileText := r.URL.Query().Get("profile")

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

	SendOK(w, r, nil, h.Logger)
}

// GetProfile handles GET /presence/getProfile requests to retrieve user's profile.
func (h *PresenceHandler) GetProfile(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	targetSN := r.URL.Query().Get("sn")
	if targetSN == "" {
		targetSN = session.ScreenName.String()
	}

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

	responseData := &ProfileData{ScreenName: targetSN, Profile: profileText}

	SendOK(w, r, responseData, h.Logger)
}

// Icon handles GET /presence/icon requests for presence icons.
func (h *PresenceHandler) Icon(w http.ResponseWriter, r *http.Request) {
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
	// occupied and dnd have no badge of their own and both mean unavailable.
	case "away", "occupied", "dnd":
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
func statusBitState(info wire.TLVUserInfo, isAIMCaller bool) string {
	status, ok := info.Uint32BE(wire.OServiceUserInfoStatus)
	if !ok {
		return ""
	}
	return statusMaskState(status, isAIMCaller)
}

// statusMaskState names the web state a status bitmask describes, or "" when
// neither Busy nor DND is set.
func statusMaskState(status uint32, isAIMCaller bool) string {
	var st string
	switch {
	case status&wire.OServiceUserStatusBusy != 0:
		st = "occupied"
	case status&wire.OServiceUserStatusDND != 0:
		st = "dnd"
	default:
		return ""
	}
	if isAIMCaller {
		return "away"
	}
	return st
}

// selfWebState maps a user's own user info block to the web state string the
// clients expect ("online", "away", "idle", "invisible", "occupied", "dnd").
// Invisibility yields "invisible", not the "offline" a buddy sees.
func selfWebState(info wire.TLVUserInfo, isAIMCaller bool) string {
	if info.IsInvisible() {
		return "invisible"
	}
	if st := statusBitState(info, isAIMCaller); st != "" {
		return st
	}
	if info.IsAway() {
		return "away"
	}
	if mask, ok := info.Uint32BE(wire.OServiceUserInfoStatus); ok && mask&wire.OServiceUserStatusAway != 0 {
		return "away"
	}
	if idle, ok := info.Uint16BE(wire.OServiceUserInfoIdleTime); ok && idle > 0 {
		return "idle"
	}
	return "online"
}

// userInfoCaps returns the capability UUIDs a user info block advertises.
func userInfoCaps(info wire.TLVUserInfo) [][16]byte {
	b, ok := info.Bytes(wire.OServiceUserInfoOscarCaps)
	if !ok {
		return nil
	}
	caps := make([][16]byte, 0, len(b)/16)
	for chunk := range slices.Chunk(b, 16) {
		if len(chunk) < 16 {
			break
		}
		caps = append(caps, [16]byte(chunk))
	}
	return caps
}

// moodIconURL returns the mood icon URL for the mood advertised in caps, or ""
// when there is none. A mood supersedes webState on the client, so a user who is
// not visibly online never gets one.
func moodIconURL(baseURL, webState string, caps [][16]byte) string {
	if webState == "offline" || webState == "invisible" {
		return ""
	}
	for _, c := range caps {
		if m, ok := wire.MoodByCap(c); ok {
			return baseURL + "/mood?id=" + wire.MoodIconID(m.ID)
		}
	}
	return ""
}
