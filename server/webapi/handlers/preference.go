package handlers

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PreferenceHandler handles Web AIM API preference-related endpoints.
type PreferenceHandler struct {
	FeedbagService    FeedbagService
	SessionManager    *state.WebAPISessionManager
	PreferenceManager PreferenceManager
	Logger            *slog.Logger
}

// PreferenceManager provides methods to manage user preferences.
type PreferenceManager interface {
	SetPreferences(ctx context.Context, screenName state.IdentScreenName, prefs map[string]interface{}) error
	GetPreferences(ctx context.Context, screenName state.IdentScreenName) (map[string]interface{}, error)
}

// PermitDenyData contains permit/deny list information.
type PermitDenyData struct {
	PDMode     string   `json:"pdMode" xml:"pdMode"`
	PermitList []string `json:"allows,omitempty" xml:"allows>user,omitempty"`
	DenyList   []string `json:"blocks,omitempty" xml:"blocks>user,omitempty"`
}

// SetPreferences handles GET /preference/set requests to update user preferences.
func (h *PreferenceHandler) SetPreferences(w http.ResponseWriter, r *http.Request) {
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

	// Parse preferences from query parameters
	prefs := make(map[string]interface{})

	// Common preference keys from the Web AIM API spec
	prefKeys := []string{
		"statusMsg", "awayMsg", "profileMsg", "buddyIcon",
		"soundsOn", "alertsOn", "typingStatus", "idleTime",
		"pdMode", "invisibleTo", "visibleTo", "blockList",
		"allowList", "language", "timeZone", "dateFormat",
		"showTimestamps", "fontSize", "fontFamily", "theme",
		"autoResponse", "saveHistory", "encryptMessages",
	}

	// Extract preferences from query parameters
	for _, key := range prefKeys {
		if val := r.URL.Query().Get(key); val != "" {
			// Try to parse as boolean
			if val == "true" || val == "false" {
				prefs[key] = val == "true"
			} else if num, err := strconv.Atoi(val); err == nil {
				// Try to parse as integer
				prefs[key] = num
			} else {
				// Store as string
				prefs[key] = val
			}
		}
	}

	// Allow any other parameters starting with "pref_" for extensibility
	for key, values := range r.URL.Query() {
		if strings.HasPrefix(key, "pref_") && len(values) > 0 {
			actualKey := strings.TrimPrefix(key, "pref_")
			prefs[actualKey] = values[0]
		}
	}

	// Save preferences
	if err := h.PreferenceManager.SetPreferences(ctx, session.ScreenName.IdentScreenName(), prefs); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set preferences", "err", err.Error())
		h.sendError(w, http.StatusInternalServerError, "failed to save preferences")
		return
	}

	h.Logger.DebugContext(ctx, "preferences updated",
		"screenName", session.ScreenName.String(),
		"prefCount", len(prefs),
	)

	// Send success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = prefs
	SendResponse(w, r, response, h.Logger)
}

// GetPreferences handles GET /preference/get requests to retrieve user preferences.
func (h *PreferenceHandler) GetPreferences(w http.ResponseWriter, r *http.Request) {
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

	// Get target user (optional, defaults to session user)
	targetUser := session.ScreenName.IdentScreenName()
	if t := r.URL.Query().Get("t"); t != "" {
		targetUser = state.NewIdentScreenName(t)
	}

	// Get all stored preferences or defaults
	allPrefs, err := h.PreferenceManager.GetPreferences(ctx, targetUser)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to get preferences", "err", err.Error())
		allPrefs = h.getDefaultPreferences()
	}
	if len(allPrefs) == 0 {
		allPrefs = h.getDefaultPreferences()
	}

	// Check if specific preferences are being requested
	requestedPrefs := make(map[string]interface{})
	defaultPrefs := h.getDefaultPreferences()

	// Check each known preference key in the query parameters
	// When a preference appears in the query (e.g., playIMSound=1),
	// the client is requesting that specific preference value
	for key := range defaultPrefs {
		if r.URL.Query().Has(key) {
			// Client is requesting this specific preference
			if prefValue, exists := allPrefs[key]; exists {
				requestedPrefs[key] = prefValue
			} else {
				requestedPrefs[key] = defaultPrefs[key]
			}
		}
	}

	// If no specific preferences were requested, return all
	var prefs map[string]interface{}
	if len(requestedPrefs) > 0 {
		prefs = requestedPrefs
	} else {
		prefs = allPrefs
	}

	h.Logger.DebugContext(ctx, "preferences retrieved",
		"screenName", targetUser.String(),
		"prefCount", len(prefs),
		"requested", len(requestedPrefs) > 0,
	)

	// Check for AMF format to handle special Gromit compatibility requirements
	format := strings.ToLower(r.URL.Query().Get("f"))
	if format == "amf" || format == "amf3" {
		// Convert string "1"/"0" to numeric values for Gromit compatibility
		// Gromit expects numeric values for boolean preferences
		convertedPrefs := make(map[string]interface{})
		for key, val := range prefs {
			if strVal, ok := val.(string); ok {
				switch strVal {
				case "1":
					convertedPrefs[key] = 1
				case "0":
					convertedPrefs[key] = 0
				default:
					// Keep non-boolean values as strings
					convertedPrefs[key] = val
				}
			} else {
				convertedPrefs[key] = val
			}
		}
		prefs = convertedPrefs

		h.Logger.DebugContext(ctx, "AMF preference response",
			"prefs", prefs,
			"prefCount", len(prefs),
			"format", format,
		)

		// Ensure prefs is never nil or empty for Gromit
		if len(prefs) == 0 {
			// If no preferences found, at least return the requested ones with defaults
			if len(requestedPrefs) > 0 {
				prefs = requestedPrefs
			} else {
				// Return playIMSound as default if nothing else
				prefs = map[string]interface{}{
					"playIMSound": 1,
				}
			}
		}

		// For single preference requests, return directly for Gromit compatibility
		// For multiple preferences, wrap in jsonData
		if len(prefs) != 1 {
			prefs = map[string]interface{}{
				"jsonData": prefs,
			}
		}
	}

	// Send response in requested format
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = prefs
	SendResponse(w, r, response, h.Logger)
}

// SetPermitDeny handles GET /preference/setPermitDeny requests to update permit/deny settings.
func (h *PreferenceHandler) SetPermitDeny(w http.ResponseWriter, r *http.Request) {
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

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	fb, err := h.FeedbagService.Query(r.Context(), session.OSCARSession, frame)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)

	// Get pdMode parameter
	pdModeStr := r.URL.Query().Get("pdMode")
	if pdModeStr != "" {
		switch pdModeStr { // todo: are the string ints possible inputs?
		case "permitAll", "1":
			fl.SetMode(uint8(wire.FeedbagPDModePermitAll))
		case "denyAll", "2":
			fl.SetMode(uint8(wire.FeedbagPDModeDenyAll))
		case "permitSome", "3":
			fl.SetMode(uint8(wire.FeedbagPDModePermitSome))
		case "denySome", "4":
			fl.SetMode(uint8(wire.FeedbagPDModeDenySome))
		case "permitOnList", "5":
			fl.SetMode(uint8(wire.FeedbagPDModePermitOnList))
		default:
			h.sendError(w, http.StatusBadRequest, "invalid pdMode value")
			return
		}
	}

	// Handle permit list updates
	if pdAllow := r.URL.Query().Get("pdAllow"); pdAllow != "" {
		users := strings.Split(pdAllow, ",")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				fl.PermitUser(user)
			}
		}
	}

	if pdAllowRemove := r.URL.Query().Get("pdAllowRemove"); pdAllowRemove != "" {
		users := strings.Split(pdAllowRemove, ",")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				fl.DeletePermit(user)
			}
		}
	}

	// Handle deny list updates
	if pdBlock := r.URL.Query().Get("pdBlock"); pdBlock != "" {
		users := strings.Split(pdBlock, ",")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				fl.DenyUser(user)
			}
		}
	}

	if pdBlockRemove := r.URL.Query().Get("pdBlockRemove"); pdBlockRemove != "" {
		users := strings.Split(pdBlockRemove, ",")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				fl.DeleteDeny(user)
			}
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := h.FeedbagService.UpsertItem(ctx, session.OSCARSession, frame, pending); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set PD mode", "err", err.Error())
			h.sendError(w, http.StatusInternalServerError, "failed to update PD mode")
			return
		}
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		body := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := h.FeedbagService.DeleteItem(ctx, session.OSCARSession, frame, body); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set PD mode", "err", err.Error())
			h.sendError(w, http.StatusInternalServerError, "failed to update PD mode")
			return
		}
	}

	pdd := permitDenyData(fl.Items())

	h.Logger.DebugContext(ctx, "permit/deny settings updated",
		"screenName", session.ScreenName.String(),
		"pdMode", pdd.PDMode,
		"permitCount", len(pdd.PermitList),
		"denyCount", len(pdd.DenyList),
	)

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = pdd
	SendResponse(w, r, response, h.Logger)
}

func permitDenyData(fl []wire.FeedbagItem) PermitDenyData {
	pdd := PermitDenyData{}
	for _, item := range fl {
		switch item.ClassID {
		case wire.FeedbagClassIDDeny:
			pdd.DenyList = append(pdd.DenyList, item.Name)
		case wire.FeedbagClassIDPermit:
			pdd.PermitList = append(pdd.PermitList, item.Name)
		case wire.FeedbagClassIdPdinfo:
			mode, _ := item.Uint8(wire.FeedbagAttributesPdMode)
			switch wire.FeedbagPDMode(mode) {
			case wire.FeedbagPDModePermitAll:
				pdd.PDMode = "permitAll"
			case wire.FeedbagPDModeDenyAll:
				pdd.PDMode = "denyAll"
			case wire.FeedbagPDModePermitSome:
				pdd.PDMode = "permitSome"
			case wire.FeedbagPDModeDenySome:
				pdd.PDMode = "denySome"
			case wire.FeedbagPDModePermitOnList:
				pdd.PDMode = "permitOnList"
			}
		}
	}
	return pdd
}

// GetPermitDeny handles GET /preference/getPermitDeny requests to retrieve permit/deny settings.
func (h *PreferenceHandler) GetPermitDeny(w http.ResponseWriter, r *http.Request) {
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

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	fb, err := h.FeedbagService.Query(r.Context(), session.OSCARSession, frame)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	pdd := permitDenyData(reply.Items)
	h.Logger.DebugContext(ctx, "permit/deny settings retrieved",
		"screenName", session.ScreenName.String(),
		"pdMode", pdd.PDMode,
		"permitCount", len(pdd.PermitList),
		"denyCount", len(pdd.DenyList),
	)

	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = pdd
	SendResponse(w, r, response, h.Logger)
}

// sendError sends an error response in Web AIM API format.
// getDefaultPreferences returns default preference values that clients expect.
func (h *PreferenceHandler) getDefaultPreferences() map[string]interface{} {
	return map[string]interface{}{
		"autoPlay":            "1",
		"playIMSound":         "1",
		"playBuddySound":      "1",
		"showTimestamps":      "1",
		"showAdsFlag":         "1",
		"soundSetting":        "1",
		"awayMessageOn":       "0",
		"awayMessage":         "",
		"confirmSignOff":      "0",
		"skipNavigator":       "1",
		"displayIdleTime":     "1",
		"repliesAnyone":       "0",
		"repliesUsersOnline":  "0",
		"repliesBuddies":      "0",
		"replyMessage":        "",
		"allowAccessPresence": "0",
		"blockIdleStatus":     "0",
		"reportIdleTyping":    "1",
		"smileysDisabled":     "0",
		"sortBuddiesAlpha":    "0",
		"statusMsg":           "",
		"statusIcon":          "",
		"skin":                "default",
	}
}

func (h *PreferenceHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	// todo log
	SendError(w, statusCode, message)
}
