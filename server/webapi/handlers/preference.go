package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PreferenceHandler handles Web AIM API preference-related endpoints.
type PreferenceHandler struct {
	FeedbagService FeedbagService
	SessionManager *state.WebAPISessionManager
	Logger         *slog.Logger
}

// webBuddyPrefs maps Web AIM API preference names to OSCAR buddy-pref bit
// numbers, which are stored as a bitmask in the user's feedbag (see
// wire.BuddyPref). Default values for absent prefs are owned by wire.BuddyPref,
// not here.
var webBuddyPrefs = map[string]uint16{
	"displayLogin":                wire.FeedbagBuddyPrefsDisplayLogin,
	"displayEBuddy":               wire.FeedbagBuddyPrefsDisplayEBuddy,
	"playEnter":                   wire.FeedbagBuddyPrefsPlayEnter,
	"playExit":                    wire.FeedbagBuddyPrefsPlayExit,
	"viewIMTimestamps":            wire.FeedbagBuddyPrefsViewIMStamp,
	"viewSmilies":                 wire.FeedbagBuddyPrefsViewSmileys,
	"acceptIcons":                 wire.FeedbagBuddyPrefsAcceptIcons,
	"knockNonAOLIMs":              wire.FeedbagBuddyPrefsKnockNonAOLIMs,
	"knockNonListIMs":             wire.FeedbagBuddyPrefsKnockNonListIMs,
	"discloseIdle":                wire.FeedbagBuddyPrefsDiscloseIdle,
	"acceptCustomBart":            wire.FeedbagBuddyPrefsAcceptCustomBart,
	"acceptNonListBart":           wire.FeedbagBuddyPrefsAcceptNonListBart,
	"acceptBgs":                   wire.FeedbagBuddyPrefsAcceptBgs,
	"acceptChromes":               wire.FeedbagBuddyPrefsAcceptChromes,
	"acceptBLSounds":              wire.FeedbagBuddyPrefsAcceptBLSounds,
	"acceptIMsounds":              wire.FeedbagBuddyPrefsAcceptIMSounds,
	"noSeeRecentBuddies":          wire.FeedbagBuddyPrefsNoSeeRecentBuddies,
	"acceptSMSLegal":              wire.FeedbagBuddyPrefsAcceptSMSLegal,
	"enterDoesCRLF":               wire.FeedbagBuddyPrefsEnterDoesCRLF,
	"playIMSound":                 wire.FeedbagBuddyPrefsPlayIMSound,
	"discloseTyping":              wire.FeedbagBuddyPrefsDiscloseTyping,
	"acceptSuperIcons":            wire.FeedbagBuddyPrefsAcceptSuperIcons,
	"acceptBLRichText":            wire.FeedbagBuddyPrefsAcceptBLRichText,
	"reduceIMSound":               wire.FeedbagBuddyPrefsReduceIMSound,
	"confirmDirectIM":             wire.FeedbagBuddyPrefsConfirmDirectIM,
	"oneTabbedIMWindow":           wire.FeedbagBuddyPrefsOneTabbedIMWindow,
	"buddyInfoOnMouseover":        wire.FeedbagBuddyPrefsBuddyInfoOnMouseover,
	"discloseBuddyMatches":        wire.FeedbagBuddyPrefsDiscloseBuddyMatches,
	"catchIMs":                    wire.FeedbagBuddyPrefsCatchIMs,
	"showFriendlyName":            wire.FeedbagBuddyPrefsShowFriendlyName,
	"discloseRadio":               wire.FeedbagBuddyPrefsDiscloseRadio,
	"showCapabilities":            wire.FeedbagBuddyPrefsShowCapabilities,
	"showBuddyListFilter":         wire.FeedbagBuddyPrefsShowBuddyListFilter,
	"showAwayIdle":                wire.FeedbagBuddyPrefsShowAwayIdle,
	"showMobile":                  wire.FeedbagBuddyPrefsShowMobile,
	"sortBuddyList":               wire.FeedbagBuddyPrefsSortBuddyList,
	"catchIMsForClient":           wire.FeedbagBuddyPrefsCatchIMsForClient,
	"newMessageSmallNotification": wire.FeedbagBuddyPrefsNewMessageSmallNotify,
	"noFrequentBuddies":           wire.FeedbagBuddyPrefsNoFrequentBuddies,
	"blogAwayMessages":            wire.FeedbagBuddyPrefsBlogAwayMessages,
	"blogAIMSigMessages":          wire.FeedbagBuddyPrefsBlogAIMSigMessages,
	"blogNoComments":              wire.FeedbagBuddyPrefsBlogNoComments,
	"friendOfFriend":              wire.FeedbagBuddyPrefsFriendOfFriend,
	"friendGetContactList":        wire.FeedbagBuddyPrefsFriendGetContactList,
	"compadInit":                  wire.FeedbagBuddyPrefsCompadInit,
	"sendBuddyFeed":               wire.FeedbagBuddyPrefsSendBuddyFeed,
	"blkSendIMWhileAway":          wire.FeedbagBuddyPrefsBlkSendIMWhileAway,
	"showBuddyFeed":               wire.FeedbagBuddyPrefsShowBuddyFeed,
	"noSaveVanityInfo":            wire.FeedbagBuddyPrefsNoSaveVanityInfo,
	"acceptOffLineIM":             wire.FeedbagBuddyPrefsAcceptOfflineIM,
	"showGroups":                  wire.FeedbagBuddyPrefsShowGroups,
	"sortGroup":                   wire.FeedbagBuddyPrefsSortGroup,
	"showOffLineBuddies":          wire.FeedbagBuddyPrefsShowOfflineBuddies,
	"expandBuddies":               wire.FeedbagBuddyPrefsExpandBuddies,
	"thirdPartyFeeds":             wire.FeedbagBuddyPrefsThirdPartyFeeds,
	"notifyReceivedInvite":        wire.FeedbagBuddyPrefsNotifyReceivedInvite,
	"apfAutoAccept":               wire.FeedbagBuddyPrefsApfAutoAccept,
	"apfAutoAcceptBuddy":          wire.FeedbagBuddyPrefsApfAutoAcceptBuddy,
	"blockAwayMsgFeed":            wire.FeedbagBuddyPrefsBlockAwayMsgFeed,
	"blockAIMProfileFeed":         wire.FeedbagBuddyPrefsBlockAIMProfileFeed,
	"blockAIMPagesFeed":           wire.FeedbagBuddyPrefsBlockAIMPagesFeed,
	"blockJournalsFeed":           wire.FeedbagBuddyPrefsBlockJournalsFeed,
	"blockLocationFeed":           wire.FeedbagBuddyPrefsBlockLocationFeed,
	"blockStickiesFeed":           wire.FeedbagBuddyPrefsBlockStickiesFeed,
	"blockUncutFeed":              wire.FeedbagBuddyPrefsBlockUncutFeed,
	"blockLinksFeed":              wire.FeedbagBuddyPrefsBlockLinksFeed,
	"blockAIMBulletinFeed":        wire.FeedbagBuddyPrefsBlockAIMBulletinFeed,
	"saveStatusMsg":               wire.FeedbagBuddyPrefsSaveStatusMsg,
	// Not in the spec Preferences enum, but sent by the web client.
	"apfNotifyReceivedInviteByEmail": wire.FeedbagBuddyPrefsApfNotifyReceivedByEmail,
	"showOfflineGrp":                 wire.FeedbagBuddyPrefsShowOfflineGrp,
	"offlineGrpCollapsed":            wire.FeedbagBuddyPrefsOfflineGrpCollapsed,
	"firstImSoundOnly":               wire.FeedbagBuddyPrefsFirstIMSoundOnly,
	"imblastInviteNotify":            wire.FeedbagBuddyPrefsImblastInviteNotify,

	// Web-client-only preferences with no OSCAR buddy-pref equivalent. OSCAR
	// defines prefs through 0x4B, so we persist these in the same feedbag
	// buddy-prefs bitmask at positions above that range; no real OSCAR client
	// reads or writes these bits.
	"viewIMsInBubbles":           wire.FeedbagBuddyPrefsViewIMsInBubbles,
	"viewIMTimestampsRelative":   wire.FeedbagBuddyPrefsViewIMTimestampsRelative,
	"globalOTR":                  wire.FeedbagBuddyPrefsGlobalOTR,
	"imblastInviteFromBuddyOnly": wire.FeedbagBuddyPrefsImblastInviteFromBuddyOnly,
}

// PermitDenyData contains permit/deny list information.
type PermitDenyData struct {
	PDMode     string   `json:"pdMode" xml:"pdMode"`
	PermitList []string `json:"allows,omitempty" xml:"allows>user,omitempty"`
	DenyList   []string `json:"blocks,omitempty" xml:"blocks>user,omitempty"`
}

// SetPreferences handles GET /preference/set requests to update user preferences.
func (h *PreferenceHandler) SetPreferences(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	// Preferences are stored as OSCAR buddy prefs in the feedbag, which requires
	// an OSCAR session to act on behalf of.
	instance := session.OSCARSession

	// Read-modify-write the buddy-prefs item so bits the web client doesn't
	// manage (e.g. the typing-events bit consumed by the OSCAR session) survive.
	item, err := buddyPrefsItem(ctx, h.FeedbagService, instance)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	applied := make(map[string]interface{})
	for name, pref := range webBuddyPrefs {
		val := r.URL.Query().Get(name)
		if val == "" {
			continue
		}
		on := parseBoolPref(val)
		item.TLVList = wire.SetBuddyPref(item.TLVList, pref, on)
		applied[name] = boolToPrefInt(on)
	}

	if len(applied) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := h.FeedbagService.UpsertItem(ctx, instance, frame, []wire.FeedbagItem{item}); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set preferences", "err", err.Error())
			h.sendError(w, http.StatusInternalServerError, "failed to save preferences")
			return
		}

		// Notify the client's open windows via the event stream so display
		// changes (e.g. bubbles/classic) take effect immediately without a
		// browser refresh.
		session.EventQueue.Push(types.EventTypePreference, applied)
	}

	h.Logger.DebugContext(ctx, "preferences updated",
		"screenName", session.ScreenName.String(),
		"prefCount", len(applied),
	)

	// Send success response
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = applied
	SendResponse(w, r, response, h.Logger)
}

// GetPreferences handles GET /preference/get requests to retrieve user preferences.
func (h *PreferenceHandler) GetPreferences(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	// Load the buddy-prefs bitmask from the feedbag. Absent prefs fall back to
	// the spec default.
	var prefsList wire.TLVList
	if item, err := buddyPrefsItem(ctx, h.FeedbagService, session.OSCARSession); err != nil {
		h.Logger.WarnContext(ctx, "failed to get preferences", "err", err.Error())
	} else {
		prefsList = item.TLVList
	}

	// When specific preferences are named in the query (e.g. playIMSound=1), the
	// client is selecting those; otherwise return all preferences.
	requestedPrefs := make(map[string]interface{})
	for name, pref := range webBuddyPrefs {
		if r.URL.Query().Has(name) {
			requestedPrefs[name] = effectivePrefValue(prefsList, pref)
		}
	}

	var prefs map[string]interface{}
	if len(requestedPrefs) > 0 {
		prefs = requestedPrefs
	} else {
		prefs = make(map[string]interface{}, len(webBuddyPrefs))
		for name, pref := range webBuddyPrefs {
			prefs[name] = effectivePrefValue(prefsList, pref)
		}
	}

	h.Logger.DebugContext(ctx, "preferences retrieved",
		"screenName", session.ScreenName.String(),
		"prefCount", len(prefs),
		"requested", len(requestedPrefs) > 0,
	)

	// AMF clients (e.g. Gromit) expect the payload shaped a specific way. Pref
	// values are already numeric 0/1, which is what these clients expect.
	format := strings.ToLower(r.URL.Query().Get("f"))
	if format == "amf" || format == "amf3" {
		// Ensure prefs is never empty for Gromit.
		if len(prefs) == 0 {
			prefs = map[string]interface{}{"playIMSound": 1}
		}
		// A single preference is returned directly; multiple are wrapped in
		// jsonData for Gromit compatibility.
		if len(prefs) != 1 {
			prefs = map[string]interface{}{"jsonData": prefs}
		}

		h.Logger.DebugContext(ctx, "AMF preference response",
			"prefCount", len(prefs),
			"format", format,
		)
	}

	// Send response in requested format
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = prefs
	SendResponse(w, r, response, h.Logger)
}

// buddyPrefsItem returns the user's buddy-prefs feedbag item, creating a fresh
// (empty) one if the feedbag does not have it yet.
func buddyPrefsItem(ctx context.Context, fs FeedbagService, instance *state.SessionInstance) (wire.FeedbagItem, error) {
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	fb, err := fs.Query(ctx, instance, frame)
	if err != nil {
		return wire.FeedbagItem{}, err
	}
	reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return wire.FeedbagItem{}, fmt.Errorf("unexpected feedbag reply type")
	}
	for _, item := range reply.Items {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs {
			return item, nil
		}
	}
	// No buddy-prefs item yet; create one. Only a single item of this class is
	// allowed, with an empty name and no group.
	return wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdBuddyPrefs,
		ItemID:  uint16(rand.Intn(0xFFFF)),
	}, nil
}

// effectiveBuddyPrefs returns the 0/1 value of every web buddy pref, using the
// feedbag value when the pref's valid bit is set and the spec default otherwise.
// This mirrors GetPreferences so the pushed preference event and the
// preference/get endpoint agree: server-side defaults (e.g. showGroups) reach
// the client even for prefs the user has never explicitly set. The web client
// reads these from the startup preference event and has no other default for
// them, so an omitted pref would silently fall back to the client's own hidden
// default (which, for showGroups, hides group headers).
func effectiveBuddyPrefs(list wire.TLVList) map[string]interface{} {
	prefs := make(map[string]interface{}, len(webBuddyPrefs))
	for name, pref := range webBuddyPrefs {
		prefs[name] = effectivePrefValue(list, pref)
	}
	return prefs
}

// effectivePrefValue returns the 0/1 value for the buddy pref prefNum, deferring
// to wire.BuddyPref for both the stored value and its default. Values are emitted
// as numbers (not "1"/"0" strings) because the web client evaluates them with
// JavaScript truthiness/numeric comparisons, where the string "0" is truthy.
func effectivePrefValue(list wire.TLVList, prefNum uint16) int {
	return boolToPrefInt(wire.BuddyPref(list, prefNum))
}

// parseBoolPref interprets a Web API preference query value as a boolean.
func parseBoolPref(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func boolToPrefInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SetPermitDeny handles GET /preference/setPermitDeny requests to update permit/deny settings.
func (h *PreferenceHandler) SetPermitDeny(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

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
func (h *PreferenceHandler) GetPermitDeny(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

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

func (h *PreferenceHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	// todo log
	SendError(w, statusCode, message)
}
