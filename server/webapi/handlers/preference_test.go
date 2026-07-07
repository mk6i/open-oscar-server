package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// buddyPrefsFeedbag builds a feedbag reply carrying a single buddy-prefs item
// with the given prefs pre-set.
func buddyPrefsFeedbag(prefs map[uint16]bool) wire.SNACMessage {
	var list wire.TLVList
	for num, val := range prefs {
		list = wire.SetBuddyPref(list, num, val)
	}
	return wire.SNACMessage{
		Body: wire.SNAC_0x13_0x06_FeedbagReply{
			Items: []wire.FeedbagItem{
				{ClassID: wire.FeedbagClassIdBuddyPrefs, ItemID: 1, TLVLBlock: wire.TLVLBlock{TLVList: list}},
			},
		},
	}
}

func TestPreferenceHandler_SetPreferences(t *testing.T) {
	fs := &MockFeedbagService{}
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	// Existing feedbag already has acceptCustomBart (0x0B, default false) enabled;
	// it must survive the read-modify-write. Using a default-false pref means an
	// observed true value can only come from the stored bit, not the default.
	fs.On("Query", mock.Anything, oscarInstance, mock.Anything).
		Return(buddyPrefsFeedbag(map[uint16]bool{wire.FeedbagBuddyPrefsAcceptCustomBart: true}), nil)

	var upserted []wire.FeedbagItem
	fs.On("UpsertItem", mock.Anything, oscarInstance, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { upserted = args.Get(3).([]wire.FeedbagItem) }).
		Return(nil, nil)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: fs,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/set?aimsid="+aimsid+"&playIMSound=0&discloseTyping=1", nil)
	rr := httptest.NewRecorder()
	handler.SetPreferences(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	if assert.Len(t, upserted, 1) {
		item := upserted[0]
		assert.Equal(t, wire.FeedbagClassIdBuddyPrefs, item.ClassID)

		assertPref := func(num uint16, want bool) {
			assert.Equalf(t, want, wire.BuddyPref(item.TLVList, num), "pref 0x%02x", num)
		}
		assertPref(wire.FeedbagBuddyPrefsAcceptCustomBart, true) // preserved (default false)
		assertPref(0x15, false)                                  // playIMSound off (default true)
		assertPref(0x16, true)                                   // discloseTyping on
	}
	fs.AssertExpectations(t)
}

func TestPreferenceHandler_GetPreferences_Selected(t *testing.T) {
	fs := &MockFeedbagService{}
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	// playIMSound (0x15) explicitly disabled in the feedbag.
	fs.On("Query", mock.Anything, oscarInstance, mock.Anything).
		Return(buddyPrefsFeedbag(map[uint16]bool{0x15: false}), nil)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: fs,
		Logger:         slog.Default(),
	}

	// Request two prefs: playIMSound (stored=false) and acceptIcons (unset -> default true).
	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+aimsid+"&playIMSound&acceptIcons", nil)
	rr := httptest.NewRecorder()
	handler.GetPreferences(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"playIMSound":0`)
	assert.Contains(t, body, `"acceptIcons":1`)
	// Only the two requested prefs should be present.
	assert.NotContains(t, body, `"displayLogin"`)
}

func TestPreferenceHandler_GetPreferences_All(t *testing.T) {
	fs := &MockFeedbagService{}
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	// Empty feedbag -> every pref resolves to its spec default.
	fs.On("Query", mock.Anything, oscarInstance, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: fs,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+aimsid, nil)
	rr := httptest.NewRecorder()
	handler.GetPreferences(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"displayLogin":1`)     // default true
	assert.Contains(t, body, `"acceptCustomBart":0`) // default false
}

func TestPreferenceHandler_GetPreferences_AMF(t *testing.T) {
	fs := &MockFeedbagService{}
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	fs.On("Query", mock.Anything, oscarInstance, mock.Anything).
		Return(buddyPrefsFeedbag(map[uint16]bool{0x15: false}), nil)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: fs,
		Logger:         slog.Default(),
	}

	// Single-pref AMF request returns a numeric value (not wrapped in jsonData).
	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+aimsid+"&f=amf&playIMSound", nil)
	rr := httptest.NewRecorder()
	handler.GetPreferences(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	// AMF-encoded response: the value is a numeric 0 (AMF integer marker 0x04
	// followed by 0x00), not the string "0".
	assert.Contains(t, body, "playIMSound\x04\x00")
	assert.NotContains(t, body, `playIMSound":"0"`)
}

func TestEffectiveBuddyPrefs_StoredOverridesDefault(t *testing.T) {
	// playIMSound defaults true but is stored false; viewIMsInBubbles defaults
	// true and is stored true. Stored (valid) values must win over defaults.
	var list wire.TLVList
	list = wire.SetBuddyPref(list, wire.FeedbagBuddyPrefsPlayIMSound, false)
	list = wire.SetBuddyPref(list, wire.FeedbagBuddyPrefsViewIMsInBubbles, true)

	got := effectiveBuddyPrefs(list)

	// Every pref is present (defaults applied for unset ones).
	assert.Len(t, got, len(webBuddyPrefs))
	assert.Equal(t, 0, got["playIMSound"])
	assert.Equal(t, 1, got["viewIMsInBubbles"])
}

func TestEffectiveBuddyPrefs_AppliesDefaultsWhenNothingSet(t *testing.T) {
	got := effectiveBuddyPrefs(wire.TLVList{})

	// Unset prefs resolve to their spec defaults rather than being omitted.
	assert.Len(t, got, len(webBuddyPrefs))
	assert.Equal(t, 1, got["showGroups"], "showGroups should default to shown")
	assert.Equal(t, 1, got["playIMSound"], "playIMSound defaults true")
	assert.Equal(t, 0, got["sortBuddyList"], "sortBuddyList defaults false")
}

func TestPreferenceHandler_SetPreferences_NoOSCARSession(t *testing.T) {
	fs := &MockFeedbagService{}
	sessionMgr, aimsid := createTestSessionManager("webonly") // nil OSCARSession

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: fs,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/set?aimsid="+aimsid+"&playIMSound=1", nil)
	rr := httptest.NewRecorder()
	handler.SetPreferences(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	fs.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything)
	_ = strings.TrimSpace(rr.Body.String())
}
