package webapi

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"reflect"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// PreferenceHandler handles Web AIM API preference-related endpoints.
type PreferenceHandler struct {
	FeedbagService FeedbagService
	SessionManager *SessionManager
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

// PreferenceData carries Web API buddy preferences.
//
// Values are numbers, not "1"/"0" strings, because the client evaluates them
// with JavaScript truthiness and numeric comparison, where the string "0" is
// truthy. They are pointers because a preference set to 0 and a preference not
// carried at all mean different things and both occur: getPreference and
// setPreference answer with just the preferences the request named, while the
// startSession seed carries every one. A plain int could not tell the two
// apart, and the client reads its buddy-list display preferences only from
// here — an omitted showGroups falls back to a hidden client default that hides
// group headers.
//
// The fields mirror webBuddyPrefs one for one; TestPreferenceDataMatchesPrefTable
// fails if the two drift apart.
type PreferenceData struct {
	DisplayLogin                   *int `json:"displayLogin,omitempty" xml:"displayLogin,omitempty"`
	DisplayEBuddy                  *int `json:"displayEBuddy,omitempty" xml:"displayEBuddy,omitempty"`
	PlayEnter                      *int `json:"playEnter,omitempty" xml:"playEnter,omitempty"`
	PlayExit                       *int `json:"playExit,omitempty" xml:"playExit,omitempty"`
	ViewIMTimestamps               *int `json:"viewIMTimestamps,omitempty" xml:"viewIMTimestamps,omitempty"`
	ViewSmilies                    *int `json:"viewSmilies,omitempty" xml:"viewSmilies,omitempty"`
	AcceptIcons                    *int `json:"acceptIcons,omitempty" xml:"acceptIcons,omitempty"`
	KnockNonAOLIMs                 *int `json:"knockNonAOLIMs,omitempty" xml:"knockNonAOLIMs,omitempty"`
	KnockNonListIMs                *int `json:"knockNonListIMs,omitempty" xml:"knockNonListIMs,omitempty"`
	DiscloseIdle                   *int `json:"discloseIdle,omitempty" xml:"discloseIdle,omitempty"`
	AcceptCustomBart               *int `json:"acceptCustomBart,omitempty" xml:"acceptCustomBart,omitempty"`
	AcceptNonListBart              *int `json:"acceptNonListBart,omitempty" xml:"acceptNonListBart,omitempty"`
	AcceptBgs                      *int `json:"acceptBgs,omitempty" xml:"acceptBgs,omitempty"`
	AcceptChromes                  *int `json:"acceptChromes,omitempty" xml:"acceptChromes,omitempty"`
	AcceptBLSounds                 *int `json:"acceptBLSounds,omitempty" xml:"acceptBLSounds,omitempty"`
	AcceptIMsounds                 *int `json:"acceptIMsounds,omitempty" xml:"acceptIMsounds,omitempty"`
	NoSeeRecentBuddies             *int `json:"noSeeRecentBuddies,omitempty" xml:"noSeeRecentBuddies,omitempty"`
	AcceptSMSLegal                 *int `json:"acceptSMSLegal,omitempty" xml:"acceptSMSLegal,omitempty"`
	EnterDoesCRLF                  *int `json:"enterDoesCRLF,omitempty" xml:"enterDoesCRLF,omitempty"`
	PlayIMSound                    *int `json:"playIMSound,omitempty" xml:"playIMSound,omitempty"`
	DiscloseTyping                 *int `json:"discloseTyping,omitempty" xml:"discloseTyping,omitempty"`
	AcceptSuperIcons               *int `json:"acceptSuperIcons,omitempty" xml:"acceptSuperIcons,omitempty"`
	AcceptBLRichText               *int `json:"acceptBLRichText,omitempty" xml:"acceptBLRichText,omitempty"`
	ReduceIMSound                  *int `json:"reduceIMSound,omitempty" xml:"reduceIMSound,omitempty"`
	ConfirmDirectIM                *int `json:"confirmDirectIM,omitempty" xml:"confirmDirectIM,omitempty"`
	OneTabbedIMWindow              *int `json:"oneTabbedIMWindow,omitempty" xml:"oneTabbedIMWindow,omitempty"`
	BuddyInfoOnMouseover           *int `json:"buddyInfoOnMouseover,omitempty" xml:"buddyInfoOnMouseover,omitempty"`
	DiscloseBuddyMatches           *int `json:"discloseBuddyMatches,omitempty" xml:"discloseBuddyMatches,omitempty"`
	CatchIMs                       *int `json:"catchIMs,omitempty" xml:"catchIMs,omitempty"`
	ShowFriendlyName               *int `json:"showFriendlyName,omitempty" xml:"showFriendlyName,omitempty"`
	DiscloseRadio                  *int `json:"discloseRadio,omitempty" xml:"discloseRadio,omitempty"`
	ShowCapabilities               *int `json:"showCapabilities,omitempty" xml:"showCapabilities,omitempty"`
	ShowBuddyListFilter            *int `json:"showBuddyListFilter,omitempty" xml:"showBuddyListFilter,omitempty"`
	ShowAwayIdle                   *int `json:"showAwayIdle,omitempty" xml:"showAwayIdle,omitempty"`
	ShowMobile                     *int `json:"showMobile,omitempty" xml:"showMobile,omitempty"`
	SortBuddyList                  *int `json:"sortBuddyList,omitempty" xml:"sortBuddyList,omitempty"`
	CatchIMsForClient              *int `json:"catchIMsForClient,omitempty" xml:"catchIMsForClient,omitempty"`
	NewMessageSmallNotification    *int `json:"newMessageSmallNotification,omitempty" xml:"newMessageSmallNotification,omitempty"`
	NoFrequentBuddies              *int `json:"noFrequentBuddies,omitempty" xml:"noFrequentBuddies,omitempty"`
	BlogAwayMessages               *int `json:"blogAwayMessages,omitempty" xml:"blogAwayMessages,omitempty"`
	BlogAIMSigMessages             *int `json:"blogAIMSigMessages,omitempty" xml:"blogAIMSigMessages,omitempty"`
	BlogNoComments                 *int `json:"blogNoComments,omitempty" xml:"blogNoComments,omitempty"`
	FriendOfFriend                 *int `json:"friendOfFriend,omitempty" xml:"friendOfFriend,omitempty"`
	FriendGetContactList           *int `json:"friendGetContactList,omitempty" xml:"friendGetContactList,omitempty"`
	CompadInit                     *int `json:"compadInit,omitempty" xml:"compadInit,omitempty"`
	SendBuddyFeed                  *int `json:"sendBuddyFeed,omitempty" xml:"sendBuddyFeed,omitempty"`
	BlkSendIMWhileAway             *int `json:"blkSendIMWhileAway,omitempty" xml:"blkSendIMWhileAway,omitempty"`
	ShowBuddyFeed                  *int `json:"showBuddyFeed,omitempty" xml:"showBuddyFeed,omitempty"`
	NoSaveVanityInfo               *int `json:"noSaveVanityInfo,omitempty" xml:"noSaveVanityInfo,omitempty"`
	AcceptOffLineIM                *int `json:"acceptOffLineIM,omitempty" xml:"acceptOffLineIM,omitempty"`
	ShowGroups                     *int `json:"showGroups,omitempty" xml:"showGroups,omitempty"`
	SortGroup                      *int `json:"sortGroup,omitempty" xml:"sortGroup,omitempty"`
	ShowOffLineBuddies             *int `json:"showOffLineBuddies,omitempty" xml:"showOffLineBuddies,omitempty"`
	ExpandBuddies                  *int `json:"expandBuddies,omitempty" xml:"expandBuddies,omitempty"`
	ThirdPartyFeeds                *int `json:"thirdPartyFeeds,omitempty" xml:"thirdPartyFeeds,omitempty"`
	NotifyReceivedInvite           *int `json:"notifyReceivedInvite,omitempty" xml:"notifyReceivedInvite,omitempty"`
	ApfAutoAccept                  *int `json:"apfAutoAccept,omitempty" xml:"apfAutoAccept,omitempty"`
	ApfAutoAcceptBuddy             *int `json:"apfAutoAcceptBuddy,omitempty" xml:"apfAutoAcceptBuddy,omitempty"`
	BlockAwayMsgFeed               *int `json:"blockAwayMsgFeed,omitempty" xml:"blockAwayMsgFeed,omitempty"`
	BlockAIMProfileFeed            *int `json:"blockAIMProfileFeed,omitempty" xml:"blockAIMProfileFeed,omitempty"`
	BlockAIMPagesFeed              *int `json:"blockAIMPagesFeed,omitempty" xml:"blockAIMPagesFeed,omitempty"`
	BlockJournalsFeed              *int `json:"blockJournalsFeed,omitempty" xml:"blockJournalsFeed,omitempty"`
	BlockLocationFeed              *int `json:"blockLocationFeed,omitempty" xml:"blockLocationFeed,omitempty"`
	BlockStickiesFeed              *int `json:"blockStickiesFeed,omitempty" xml:"blockStickiesFeed,omitempty"`
	BlockUncutFeed                 *int `json:"blockUncutFeed,omitempty" xml:"blockUncutFeed,omitempty"`
	BlockLinksFeed                 *int `json:"blockLinksFeed,omitempty" xml:"blockLinksFeed,omitempty"`
	BlockAIMBulletinFeed           *int `json:"blockAIMBulletinFeed,omitempty" xml:"blockAIMBulletinFeed,omitempty"`
	SaveStatusMsg                  *int `json:"saveStatusMsg,omitempty" xml:"saveStatusMsg,omitempty"`
	ApfNotifyReceivedInviteByEmail *int `json:"apfNotifyReceivedInviteByEmail,omitempty" xml:"apfNotifyReceivedInviteByEmail,omitempty"`
	ShowOfflineGrp                 *int `json:"showOfflineGrp,omitempty" xml:"showOfflineGrp,omitempty"`
	OfflineGrpCollapsed            *int `json:"offlineGrpCollapsed,omitempty" xml:"offlineGrpCollapsed,omitempty"`
	FirstImSoundOnly               *int `json:"firstImSoundOnly,omitempty" xml:"firstImSoundOnly,omitempty"`
	ImblastInviteNotify            *int `json:"imblastInviteNotify,omitempty" xml:"imblastInviteNotify,omitempty"`
	ViewIMsInBubbles               *int `json:"viewIMsInBubbles,omitempty" xml:"viewIMsInBubbles,omitempty"`
	ViewIMTimestampsRelative       *int `json:"viewIMTimestampsRelative,omitempty" xml:"viewIMTimestampsRelative,omitempty"`
	GlobalOTR                      *int `json:"globalOTR,omitempty" xml:"globalOTR,omitempty"`
	ImblastInviteFromBuddyOnly     *int `json:"imblastInviteFromBuddyOnly,omitempty" xml:"imblastInviteFromBuddyOnly,omitempty"`
}

// PermitDenyData contains permit/deny list information.
//
// The XML item names follow the spec's getPermitDeny, which nests <allow> under
// <allows> and <block> under <blocks>.
type PermitDenyData struct {
	PDMode     string   `json:"pdMode" xml:"pdMode"`
	PermitList []string `json:"allows,omitempty" xml:"allows>allow,omitempty"`
	DenyList   []string `json:"blocks,omitempty" xml:"blocks>block,omitempty"`
}

// SetPreferences handles GET /preference/set requests to update user preferences.
func (h *PreferenceHandler) SetPreferences(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	// Preferences are stored as OSCAR buddy prefs in the feedbag, which requires
	// an OSCAR session to act on behalf of.
	instance := session.OSCARSession

	// Read-modify-write the buddy-prefs item so bits the web client doesn't
	// manage (e.g. the typing-events bit consumed by the OSCAR session) survive.
	item, err := buddyPrefsItem(ctx, h.FeedbagService, instance)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	applied := &PreferenceData{}
	for name, pref := range webBuddyPrefs {
		val := r.URL.Query().Get(name)
		if val == "" {
			continue
		}
		on := parseBoolPref(val)
		item.TLVList = wire.SetBuddyPref(item.TLVList, pref, on)
		applied.Set(name, boolToPrefInt(on))
	}

	if applied.Len() > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := h.FeedbagService.UpsertItem(ctx, instance, frame, []wire.FeedbagItem{item}); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set preferences", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to save preferences")
			return
		}

		// Notify the client's open windows via the event stream so display
		// changes (e.g. bubbles/classic) take effect immediately without a
		// browser refresh.
		session.EventQueue.Push(EventTypePreference, applied)
	}

	h.Logger.DebugContext(ctx, "preferences updated",
		"screenName", session.ScreenName.String(),
		"prefCount", applied.Len(),
	)

	// Send success response
	SendOK(w, r, applied, h.Logger)
}

// GetPreferences handles GET /preference/get requests to retrieve user preferences.
func (h *PreferenceHandler) GetPreferences(w http.ResponseWriter, r *http.Request, session *Session) {
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
	requestedPrefs := &PreferenceData{}
	for name, pref := range webBuddyPrefs {
		if r.URL.Query().Has(name) {
			requestedPrefs.Set(name, effectivePrefValue(prefsList, pref))
		}
	}

	prefs := requestedPrefs
	if prefs.Len() == 0 {
		prefs = effectiveBuddyPrefs(prefsList)
	}

	h.Logger.DebugContext(ctx, "preferences retrieved",
		"screenName", session.ScreenName.String(),
		"prefCount", prefs.Len(),
		"requested", requestedPrefs.Len() > 0,
	)

	var payload any = prefs

	// AMF clients (e.g. Gromit) expect the payload shaped a specific way. Pref
	// values are already numeric 0/1, which is what these clients expect.
	format := requestFormat(r)
	if format == "amf" || format == "amf3" {
		amfPrefs := prefs.Map()
		// Ensure prefs is never empty for Gromit.
		if len(amfPrefs) == 0 {
			amfPrefs = map[string]any{"playIMSound": 1}
		}
		// A single preference is returned directly; multiple are wrapped in
		// jsonData for Gromit compatibility.
		if len(amfPrefs) != 1 {
			amfPrefs = map[string]any{"jsonData": amfPrefs}
		}
		payload = amfPrefs

		h.Logger.DebugContext(ctx, "AMF preference response",
			"prefCount", prefs.Len(),
			"format", format,
		)
	}

	// Send response in requested format
	SendOK(w, r, payload, h.Logger)
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
func effectiveBuddyPrefs(list wire.TLVList) *PreferenceData {
	prefs := &PreferenceData{}
	for name, pref := range webBuddyPrefs {
		prefs.Set(name, effectivePrefValue(list, pref))
	}
	return prefs
}

// prefFieldIndex maps a preference name to its PreferenceData field.
var prefFieldIndex = func() map[string]int {
	t := reflect.TypeOf(PreferenceData{})
	index := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		index[name] = i
	}
	return index
}()

// Set records one preference by its Web API name, leaving every preference not
// set this way absent from the payload. It reports whether the name is one this
// server carries.
func (p *PreferenceData) Set(name string, value int) bool {
	i, ok := prefFieldIndex[name]
	if !ok {
		return false
	}
	reflect.ValueOf(p).Elem().Field(i).Set(reflect.ValueOf(&value))
	return true
}

// Get returns a preference by its Web API name and whether it is carried.
func (p *PreferenceData) Get(name string) (int, bool) {
	i, ok := prefFieldIndex[name]
	if !ok {
		return 0, false
	}
	field := reflect.ValueOf(p).Elem().Field(i)
	if field.IsNil() {
		return 0, false
	}
	return int(field.Elem().Int()), true
}

// Map returns the carried preferences keyed by Web API name, for the AMF path
// that reshapes the payload rather than sending it as-is.
func (p *PreferenceData) Map() map[string]any {
	out := make(map[string]any, len(prefFieldIndex))
	for name := range prefFieldIndex {
		if v, ok := p.Get(name); ok {
			out[name] = v
		}
	}
	return out
}

// Len reports how many preferences the payload carries.
func (p *PreferenceData) Len() int {
	fields := reflect.ValueOf(p).Elem()
	n := 0
	for i := 0; i < fields.NumField(); i++ {
		if !fields.Field(i).IsNil() {
			n++
		}
	}
	return n
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
func (h *PreferenceHandler) SetPermitDeny(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	fb, err := h.FeedbagService.Query(r.Context(), session.OSCARSession, frame)
	if err != nil {
		SendError(w, r, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		SendError(w, r, http.StatusInternalServerError, "failed to retrieve feedbag")
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
			SendError(w, r, http.StatusBadRequest, "invalid pdMode value")
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
			SendError(w, r, http.StatusInternalServerError, "failed to update PD mode")
			return
		}
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		body := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := h.FeedbagService.DeleteItem(ctx, session.OSCARSession, frame, body); err != nil {
			h.Logger.ErrorContext(ctx, "failed to set PD mode", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to update PD mode")
			return
		}
	}

	pdd := permitDenyData(fl.Items())

	// The client reads the privacy state it renders (blocked buddies, the
	// block/unblock menu label) only from the permitDeny event, and it sees no
	// SNAC for the write it just made. Without this the block takes effect
	// server-side but the UI keeps showing the buddy as unblocked.
	session.EventQueue.Push(EventTypePermitDeny, pdd)

	h.Logger.DebugContext(ctx, "permit/deny settings updated",
		"screenName", session.ScreenName.String(),
		"pdMode", pdd.PDMode,
		"permitCount", len(pdd.PermitList),
		"denyCount", len(pdd.DenyList),
	)

	SendOK(w, r, pdd, h.Logger)
}

func permitDenyData(fl []wire.FeedbagItem) PermitDenyData {
	// A feedbag with no PD info item means no restrictions, the same default the
	// feedbag store applies. The client drives its block flow off pdMode and
	// sends no permit/deny change at all when the mode is absent.
	pdd := PermitDenyData{PDMode: "permitAll"}
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
func (h *PreferenceHandler) GetPermitDeny(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	fb, err := h.FeedbagService.Query(r.Context(), session.OSCARSession, frame)
	if err != nil {
		SendError(w, r, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		SendError(w, r, http.StatusInternalServerError, "failed to retrieve feedbag")
		return
	}

	pdd := permitDenyData(reply.Items)
	h.Logger.DebugContext(ctx, "permit/deny settings retrieved",
		"screenName", session.ScreenName.String(),
		"pdMode", pdd.PDMode,
		"permitCount", len(pdd.PermitList),
		"denyCount", len(pdd.DenyList),
	)

	SendOK(w, r, pdd, h.Logger)
}
