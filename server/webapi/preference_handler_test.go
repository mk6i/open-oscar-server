package webapi

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

// buddyPrefsFeedbag builds a buddy-prefs item with the given prefs pre-set.
func buddyPrefsFeedbag(prefs map[uint16]bool) wire.FeedbagItem {
	var list wire.TLVList
	for num, val := range prefs {
		list = wire.SetBuddyPref(list, num, val)
	}
	return wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddyPrefs, ItemID: 1, TLVLBlock: wire.TLVLBlock{TLVList: list}}
}

// newPrefsSession returns a session manager holding a running session for
// "testuser" whose OSCAR server is server, with its feedbag loaded.
func newPrefsSession(t *testing.T, server *feedbagServer) (*SessionManager, *Session, *fakeConn) {
	t.Helper()
	conn := newFakeConn().answering(server.respond)
	mgr, sess := createTestSessionManager(t, "testuser", conn)
	loadTestFeedbag(t, sess)
	return mgr, sess, conn
}

func TestPreferenceHandler_SetPreferences(t *testing.T) {
	// Existing feedbag already has acceptCustomBart (0x0B, default false) enabled;
	// it must survive the read-modify-write. Using a default-false pref means an
	// observed true value can only come from the stored bit, not the default.
	server := newFeedbagServer(buddyPrefsFeedbag(map[uint16]bool{wire.FeedbagBuddyPrefsAcceptCustomBart: true}))
	sessionMgr, sess, conn := newPrefsSession(t, server)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/set?aimsid="+sess.AimSID+"&playIMSound=0&discloseTyping=1", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetPreferences).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	changes := sentFeedbagChanges(conn)
	require.Len(t, changes, 1)
	assert.Equal(t, uint16(wire.FeedbagInsertItem), changes[0].SubGroup)
	require.Len(t, changes[0].Items, 1)
	item := changes[0].Items[0]
	assert.Equal(t, wire.FeedbagClassIdBuddyPrefs, item.ClassID)
	assert.Equal(t, uint16(1), item.ItemID)

	assertPref := func(num uint16, want bool) {
		assert.Equalf(t, want, wire.BuddyPref(item.TLVList, num), "pref 0x%02x", num)
	}
	assertPref(wire.FeedbagBuddyPrefsAcceptCustomBart, true) // preserved (default false)
	assertPref(0x15, false)                                  // playIMSound off (default true)
	assertPref(0x16, true)                                   // discloseTyping on

	assert.Equal(t, server.stored(), sess.Feedbag())
}

func TestPreferenceHandler_SetPreferences_ChangeFails(t *testing.T) {
	tests := []struct {
		name string
		// limit gates the feedbag rate class.
		limit      bool
		status     func(wire.SNACMessage) []wire.SNACMessage
		wantStatus int
	}{
		{
			name: "the server rejects the change",
			status: func(wire.SNACMessage) []wire.SNACMessage {
				return []wire.SNACMessage{snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost)}
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "the feedbag rate class is limited",
			limit:      true,
			wantStatus: statusRateLimited,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer()
			server.status = tt.status
			sessionMgr, sess, _ := newPrefsSession(t, server)
			if tt.limit {
				limitRateClass(sess, wire.Feedbag, wire.FeedbagInsertItem)
			}

			handler := &PreferenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			req, _ := http.NewRequest("GET", "/preference/set?aimsid="+sess.AimSID+"&playIMSound=0", nil)
			rr := httptest.NewRecorder()
			requireSession(handler.SessionManager, handler.SetPreferences).ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, envelopeStatus(t, rr.Body.Bytes()))
			assert.Empty(t, sess.EventQueue.GetAllEvents(), "an unsaved preference is not announced")
			assert.Empty(t, sess.Feedbag())
		})
	}
}

func TestPreferenceHandler_GetPreferences_Selected(t *testing.T) {
	// playIMSound (0x15) explicitly disabled in the feedbag.
	sessionMgr, sess, _ := newPrefsSession(t, newFeedbagServer(buddyPrefsFeedbag(map[uint16]bool{0x15: false})))

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	// Request two prefs: playIMSound (stored=false) and acceptIcons (unset -> default true).
	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+sess.AimSID+"&playIMSound&acceptIcons", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPreferences).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"playIMSound":0`)
	assert.Contains(t, body, `"acceptIcons":1`)
	// Only the two requested prefs should be present.
	assert.NotContains(t, body, `"displayLogin"`)
}

func TestPreferenceHandler_GetPreferences_All(t *testing.T) {
	// Empty feedbag -> every pref resolves to its spec default.
	sessionMgr, sess, _ := newPrefsSession(t, newFeedbagServer())

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+sess.AimSID, nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPreferences).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"displayLogin":1`)     // default true
	assert.Contains(t, body, `"acceptCustomBart":0`) // default false
}

func TestPreferenceHandler_GetPreferences_AMF(t *testing.T) {
	sessionMgr, sess, _ := newPrefsSession(t, newFeedbagServer(buddyPrefsFeedbag(map[uint16]bool{0x15: false})))

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	// Single-pref AMF request returns a numeric value (not wrapped in jsonData).
	req, _ := http.NewRequest("GET", "/preference/get?aimsid="+sess.AimSID+"&f=amf&playIMSound", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPreferences).ServeHTTP(rr, req)

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
	assert.Equal(t, len(webBuddyPrefs), got.Len())
	assertPref(t, got, "playIMSound", 0)
	assertPref(t, got, "viewIMsInBubbles", 1)
}

func TestEffectiveBuddyPrefs_AppliesDefaultsWhenNothingSet(t *testing.T) {
	got := effectiveBuddyPrefs(wire.TLVList{})

	// Unset prefs resolve to their spec defaults rather than being omitted.
	assert.Equal(t, len(webBuddyPrefs), got.Len())
	assertPref(t, got, "showGroups", 1)    // showGroups should default to shown
	assertPref(t, got, "playIMSound", 1)   // playIMSound defaults true
	assertPref(t, got, "sortBuddyList", 0) // sortBuddyList defaults false
}

func TestPreferenceHandler_SetPermitDeny_QueuesPermitDenyEvent(t *testing.T) {
	// The client renders blocked buddies from the permitDeny event alone, and it
	// sees no SNAC for its own write, so the handler has to queue the new state.
	server := newFeedbagServer()
	sessionMgr, sess, conn := newPrefsSession(t, server)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/setPermitDeny?aimsid="+sess.AimSID+"&pdMode=denySome&pdBlock=BlockedUser", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetPermitDeny).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var pdd PermitDenyData
	var found bool
	for _, event := range sess.EventQueue.GetAllEvents() {
		if event.Type == EventTypePermitDeny {
			pdd, found = event.Data.(PermitDenyData)
		}
	}
	assert.True(t, found, "expected a permitDeny event to be queued")
	assert.Equal(t, "denySome", pdd.PDMode)
	assert.Equal(t, []string{"blockeduser"}, pdd.DenyList)

	changes := sentFeedbagChanges(conn)
	require.Len(t, changes, 1)
	assert.Equal(t, uint16(wire.FeedbagInsertItem), changes[0].SubGroup)
	assert.Equal(t, permitDenyData(server.stored()), permitDenyData(sess.Feedbag()))
}

func TestPreferenceHandler_SetPermitDeny_EditsLists(t *testing.T) {
	// Removals go out after the upserts, and a name both added to and removed
	// from a list in one request ends up off it.
	server := newFeedbagServer(
		wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, GroupID: 0, ItemID: 10, Name: "oldfriend"},
		wire.FeedbagItem{ClassID: wire.FeedbagClassIDDeny, GroupID: 0, ItemID: 11, Name: "pest"},
	)
	sessionMgr, sess, conn := newPrefsSession(t, server)

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/setPermitDeny?aimsid="+sess.AimSID+
		"&pdAllow=newfriend,flipper&pdAllowRemove=oldfriend,flipper&pdBlockRemove=pest", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetPermitDeny).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var subGroups []uint16
	for _, change := range sentFeedbagChanges(conn) {
		subGroups = append(subGroups, change.SubGroup)
	}
	assert.Equal(t, []uint16{wire.FeedbagInsertItem, wire.FeedbagDeleteItem}, subGroups)

	pdd := permitDenyData(server.stored())
	assert.Equal(t, []string{"newfriend"}, pdd.PermitList)
	assert.Empty(t, pdd.DenyList)
	assert.Equal(t, pdd, permitDenyData(sess.Feedbag()))
}

func TestPreferenceHandler_SetPermitDeny_InvalidModeSendsNothing(t *testing.T) {
	sessionMgr, sess, conn := newPrefsSession(t, newFeedbagServer())

	handler := &PreferenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/preference/setPermitDeny?aimsid="+sess.AimSID+"&pdMode=bogus&pdBlock=someone", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetPermitDeny).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, sentFeedbagChanges(conn))
}

func TestPermitDenyData_DefaultsToPermitAllWithoutPDInfo(t *testing.T) {
	got := permitDenyData([]wire.FeedbagItem{
		{ClassID: wire.FeedbagClassIDDeny, Name: "blockeduser"},
	})

	assert.Equal(t, "permitAll", got.PDMode)
	assert.Equal(t, []string{"blockeduser"}, got.DenyList)
}

func TestPermitDenyData_PDInfoModeWins(t *testing.T) {
	var tlvs wire.TLVList
	tlvs.Append(wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(wire.FeedbagPDModePermitSome)))

	got := permitDenyData([]wire.FeedbagItem{
		{ClassID: wire.FeedbagClassIdPdinfo, TLVLBlock: wire.TLVLBlock{TLVList: tlvs}},
		{ClassID: wire.FeedbagClassIDPermit, Name: "alloweduser"},
	})

	assert.Equal(t, "permitSome", got.PDMode)
	assert.Equal(t, []string{"alloweduser"}, got.PermitList)
}

// assertPref asserts a preference is carried and holds want.
func assertPref(t *testing.T, prefs *PreferenceData, name string, want int) {
	t.Helper()
	got, ok := prefs.Get(name)
	if assert.True(t, ok, "%s should be carried", name) {
		assert.Equal(t, want, got, "%s", name)
	}
}

// The struct and the table must describe the same set of preferences: a
// preference in the table but not the struct is silently never sent, and one in
// the struct but not the table is always absent.
func TestPreferenceDataMatchesPrefTable(t *testing.T) {
	structNames := make([]string, 0, len(prefFieldIndex))
	for name := range prefFieldIndex {
		structNames = append(structNames, name)
	}
	tableNames := make([]string, 0, len(webBuddyPrefs))
	for name := range webBuddyPrefs {
		tableNames = append(tableNames, name)
	}
	assert.ElementsMatch(t, tableNames, structNames)
}
