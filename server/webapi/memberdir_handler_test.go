package webapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func searchReply(status uint16, results ...wire.TLVBlock) wire.SNACMessage {
	body := wire.SNAC_0x0F_0x03_InfoReply{Status: status}
	body.Results.List = results
	return reply(wire.ODir, wire.ODirInfoReply, body)
}

func result(screenName, firstName, lastName string) wire.TLVBlock {
	return wire.TLVBlock{TLVList: wire.TLVList{
		wire.NewTLVBE(wire.ODirTLVScreenName, screenName),
		wire.NewTLVBE(wire.ODirTLVFirstName, firstName),
		wire.NewTLVBE(wire.ODirTLVLastName, lastName),
	}}
}

// dirRecord is the directory record of a user with the given names.
func dirRecord(firstName, lastName string) wire.SNAC_0x02_0x0C_LocateGetDirReply {
	record := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	record.Append(wire.NewTLVBE(wire.ODirTLVFirstName, firstName))
	record.Append(wire.NewTLVBE(wire.ODirTLVLastName, lastName))
	return record
}

// dirServer answers directory SNACs the way the OSCAR server does.
type dirServer struct {
	// users holds the directory record of each existing user by screen name.
	// A name with no record belongs to no user, and gets a record without
	// directory TLVs.
	users map[string]wire.SNAC_0x02_0x0C_LocateGetDirReply
	// everyone, when set, is the record of every name.
	everyone *wire.SNAC_0x02_0x0C_LocateGetDirReply
	// search answers directory searches. Without it, searches find nobody.
	search func(q wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage
	// readErr makes directory reads fail.
	readErr bool
}

func (d dirServer) respond(req wire.SNACMessage) []wire.SNACMessage {
	switch body := req.Body.(type) {
	case wire.SNAC_0x02_0x0B_LocateGetDirInfo:
		if d.readErr {
			return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotSupportedByHost)}
		}
		record, ok := d.users[body.ScreenName]
		switch {
		case d.everyone != nil:
			record = *d.everyone
		case !ok:
			record = wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
		}
		return []wire.SNACMessage{reply(wire.Locate, wire.LocateGetDirReply, record)}
	case wire.SNAC_0x0F_0x02_InfoQuery:
		if d.search == nil {
			return []wire.SNACMessage{searchReply(wire.ODirSearchResponseOK)}
		}
		return []wire.SNACMessage{d.search(body)}
	case wire.SNAC_0x02_0x09_LocateSetDirInfo:
		return []wire.SNACMessage{reply(wire.Locate, wire.LocateSetDirReply, wire.SNAC_0x02_0x0A_LocateSetDirReply{Result: 1})}
	}
	return nil
}

// newDirSession returns a running session for screenName whose OSCAR server
// is dir.
func newDirSession(t *testing.T, screenName string, dir dirServer) (*Session, *fakeConn) {
	conn := newFakeConn().answering(dir.respond)
	return newTestSessionAs(t, state.DisplayScreenName(screenName), conn), conn
}

// sentSearches returns the directory searches sent to the OSCAR server.
func sentSearches(conn *fakeConn) []wire.SNAC_0x0F_0x02_InfoQuery {
	var queries []wire.SNAC_0x0F_0x02_InfoQuery
	for _, body := range conn.sentOf(wire.ODir, wire.ODirInfoQuery) {
		queries = append(queries, body.(wire.SNAC_0x0F_0x02_InfoQuery))
	}
	return queries
}

// sentDirUpdates returns the directory updates sent to the OSCAR server.
func sentDirUpdates(conn *fakeConn) []wire.SNAC_0x02_0x09_LocateSetDirInfo {
	var updates []wire.SNAC_0x02_0x09_LocateSetDirInfo
	for _, body := range conn.sentOf(wire.Locate, wire.LocateSetDirInfo) {
		updates = append(updates, body.(wire.SNAC_0x02_0x09_LocateSetDirInfo))
	}
	return updates
}

// decodeInfoArray pulls infoArray out of the response envelope at the given
// path ("results.infoArray" for search, "infoArray" for get).
func decodeInfoArray(t *testing.T, body []byte, nested bool) []MemberDirInfo {
	t.Helper()
	var envelope struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				InfoArray []MemberDirInfo `json:"infoArray"`
				Results   struct {
					InfoArray []MemberDirInfo `json:"infoArray"`
				} `json:"results"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, 200, envelope.Response.StatusCode)
	if nested {
		return envelope.Response.Data.Results.InfoArray
	}
	return envelope.Response.Data.InfoArray
}

// envelopeStatus returns the status code in a response envelope.
func envelopeStatus(t *testing.T, body []byte) int {
	t.Helper()
	var envelope struct {
		Response struct {
			StatusCode int `json:"statusCode"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	return envelope.Response.StatusCode
}

func TestMemberDirHandler_Search_Keyword(t *testing.T) {
	session, conn := newDirSession(t, "me", dirServer{
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK, result("FoundUser", "Found", "User"))
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dhaha&nToGet=200", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "founduser", infoArray[0].Profile.AimID)
	assert.Equal(t, "FoundUser", infoArray[0].Profile.DisplayID)
	assert.Equal(t, "Found", infoArray[0].Profile.FirstName)

	// keyword=haha must map to the ODir interest TLV.
	queries := sentSearches(conn)
	require.Len(t, queries, 1)
	interest, ok := queries[0].String(wire.ODirTLVInterest)
	assert.True(t, ok)
	assert.Equal(t, "haha", interest)
}

func TestMemberDirHandler_Search_FirstLastName(t *testing.T) {
	session, conn := newDirSession(t, "me", dirServer{
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK, result("Bob", "Bob", "Smith"))
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=firstName%3DBob%2ClastName%3DSmith", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bob", infoArray[0].Profile.AimID)

	// firstName/lastName must map to the ODir name TLVs, not interest.
	queries := sentSearches(conn)
	require.Len(t, queries, 1)
	first, hasFirst := queries[0].String(wire.ODirTLVFirstName)
	last, hasLast := queries[0].String(wire.ODirTLVLastName)
	_, hasInterest := queries[0].String(wire.ODirTLVInterest)
	assert.True(t, hasFirst && hasLast)
	assert.Equal(t, "Bob", first)
	assert.Equal(t, "Smith", last)
	assert.False(t, hasInterest)
}

func TestMemberDirHandler_Search_ExcludesSelf(t *testing.T) {
	session, _ := newDirSession(t, "M E", dirServer{
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK,
				result("Me", "", ""),    // caller — must be filtered out
				result("Other", "", ""), // kept
			)
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dx", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "other", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_RespectsJSONPCallback(t *testing.T) {
	session, _ := newDirSession(t, "me", dirServer{})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dx&c=_callbacks_._abc", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	// The web client loads this via a <script> tag, so the response must be
	// JavaScript (JSONP), not application/json — otherwise the browser CORB-blocks it.
	// The charset is explicit because a script tag otherwise decodes using the host
	// page's encoding, which mangles non-ASCII screen names.
	assert.Equal(t, "application/javascript; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "_callbacks_._abc(")
}

func TestMemberDirHandler_Get_Self(t *testing.T) {
	session, conn := newDirSession(t, "me", dirServer{
		users: map[string]wire.SNAC_0x02_0x0C_LocateGetDirReply{"me": dirRecord("Me", "Myself")},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	// No "t" param: defaults to self.
	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "me", infoArray[0].Profile.AimID)
	assert.Equal(t, "Me", infoArray[0].Profile.FirstName)
	assert.Equal(t, "Myself", infoArray[0].Profile.LastName)
	assert.Equal(t, []any{wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: "me"}},
		conn.sentOf(wire.Locate, wire.LocateGetDirInfo))
}

func TestMemberDirHandler_Get_LabelsEachTargetWithOwnIdentity(t *testing.T) {
	session, _ := newDirSession(t, "Bob Smith", dirServer{
		users: map[string]wire.SNAC_0x02_0x0C_LocateGetDirReply{
			"Bob Smith": dirRecord("Bob", ""),
			"alice":     dirRecord("Alice", ""),
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid&t=Bob+Smith,alice", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	// Each result carries the identity of the target it describes, not the
	// caller's — the client keys users by aimId.
	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	require.Len(t, infoArray, 2)
	assert.Equal(t, "bobsmith", infoArray[0].Profile.AimID)
	assert.Equal(t, "Bob Smith", infoArray[0].Profile.DisplayID)
	assert.Equal(t, "Bob", infoArray[0].Profile.FirstName)
	assert.Equal(t, "alice", infoArray[1].Profile.AimID)
	assert.Equal(t, "alice", infoArray[1].Profile.DisplayID)
	assert.Equal(t, "Alice", infoArray[1].Profile.FirstName)
}

func TestMemberDirHandler_Get_CapsTargetFanOut(t *testing.T) {
	session, conn := newDirSession(t, "me", dirServer{})
	h := &MemberDirHandler{Logger: slog.Default()}

	// Every target costs a directory lookup, so an arbitrarily long "t" list
	// must not translate into an unbounded number of them.
	targets := make([]string, maxMemberDirTargets+50)
	for i := range targets {
		targets[i] = fmt.Sprintf("user%d", i)
	}
	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid&t="+strings.Join(targets, ","), nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	assert.Len(t, infoArray, maxMemberDirTargets)
	assert.Len(t, conn.sentOf(wire.Locate, wire.LocateGetDirInfo), maxMemberDirTargets)
}

func TestMemberDirHandler_Update_PersistsNameAndPreservesOtherFields(t *testing.T) {
	// Current directory record has a city set that the name form must not wipe.
	current := dirRecord("Old", "Name")
	current.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	session, conn := newDirSession(t, "mike", dirServer{
		users: map[string]wire.SNAC_0x02_0x0C_LocateGetDirReply{"mike": current},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET",
		"/memberDir/update?aimsid=sid&set=firstName%3DMike&set=lastName%3DK&set=hideLevel%3DemailsAndCellular", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	// The set request must carry the new name AND the preserved city.
	updates := sentDirUpdates(conn)
	require.Len(t, updates, 1)
	first, _ := updates[0].String(wire.ODirTLVFirstName)
	last, _ := updates[0].String(wire.ODirTLVLastName)
	city, _ := updates[0].String(wire.ODirTLVCity)
	assert.Equal(t, "Mike", first)
	assert.Equal(t, "K", last)
	assert.Equal(t, "Reno", city)
}

func TestMemberDirHandler_Update_AbortsWhenCurrentInfoUnreadable(t *testing.T) {
	session, conn := newDirSession(t, "mike", dirServer{readErr: true})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/update?aimsid=sid&set=firstName%3DMike&set=lastName%3DK", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	// SetDirectoryInfo replaces every column, so writing a record we couldn't
	// seed would blank the fields this form doesn't edit. Report the failure
	// instead.
	assert.Empty(t, sentDirUpdates(conn))
	assert.Equal(t, http.StatusInternalServerError, envelopeStatus(t, rr.Body.Bytes()))
}

func TestMemberDirHandler_Update_ReadsDoubleEncodedFormBody(t *testing.T) {
	// A form body encodes each "set" value twice — once building the pair, once
	// building the body — and arrives with no Content-Type, which is what
	// parseBodyForm's defaulting exists to handle.
	current := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	current.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	session, conn := newDirSession(t, "mike", dirServer{
		users: map[string]wire.SNAC_0x02_0x0C_LocateGetDirReply{"mike": current},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	form := url.Values{}
	form.Set("aimsid", "sid")
	form.Set("f", "json")
	form.Add("set", "firstName=Bob%20Smith")
	form.Add("set", "lastName=O%27Brien")
	form.Add("set", "gender=unknown")

	req := httptest.NewRequest("POST", "/memberDir/update", strings.NewReader(form.Encode()))
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	updates := sentDirUpdates(conn)
	require.Len(t, updates, 1)
	first, _ := updates[0].String(wire.ODirTLVFirstName)
	last, _ := updates[0].String(wire.ODirTLVLastName)
	city, _ := updates[0].String(wire.ODirTLVCity)
	// Without the second unescape these arrive as "Bob%20Smith" and
	// "O%27Brien" and are stored verbatim.
	assert.Equal(t, "Bob Smith", first)
	assert.Equal(t, "O'Brien", last)
	assert.Equal(t, "Reno", city)
}

func TestMemberDirHandler_Update_QueryValuesAreNotUnescapedTwice(t *testing.T) {
	// Query values are encoded once and are final after the query decoder runs.
	// Unescaping again would corrupt a name carrying a literal '%'.
	session, conn := newDirSession(t, "mike", dirServer{})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET",
		"/memberDir/update?aimsid=sid&set=firstName%3D100%25&set=lastName%3DSmith", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	updates := sentDirUpdates(conn)
	require.Len(t, updates, 1)
	first, _ := updates[0].String(wire.ODirTLVFirstName)
	last, _ := updates[0].String(wire.ODirTLVLastName)
	assert.Equal(t, "100%", first)
	assert.Equal(t, "Smith", last)
}

func TestMemberDirHandler_Update_ReportsRejectedUpdate(t *testing.T) {
	conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
		if _, ok := req.Body.(wire.SNAC_0x02_0x09_LocateSetDirInfo); ok {
			return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotSupportedByHost)}
		}
		return dirServer{}.respond(req)
	})
	session := newTestSessionAs(t, "mike", conn)
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/update?aimsid=sid&set=firstName%3DMike", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusInternalServerError, envelopeStatus(t, rr.Body.Bytes()))
}

func TestServer_MemberDirUpdateIsRoutedForGETAndPOST(t *testing.T) {
	// Go 1.22 mux patterns are method-exact, so registering only GET sends a POST to
	// the catch-all 404. Neither request below carries an aimsid, so a routed one
	// is rejected by the session middleware (400) and an unrouted one 404s.
	srv := NewServer([]string{"127.0.0.1:0"}, slog.Default(), Handler{Logger: slog.Default()},
		NewSessionManager())
	require.NotEmpty(t, srv.servers)
	mux := srv.servers[0].Handler

	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/memberDir/update", strings.NewReader(""))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			assert.NotEqual(t, http.StatusNotFound, rr.Code,
				"%s /memberDir/update is not registered", method)
		})
	}
}

func TestMemberDirHandler_Search_MatchesScreenName(t *testing.T) {
	// An add-contact box that takes an email or UIN sends the value as keyword, but
	// ODir searches interests, names and email — never the screen name.
	bob := dirRecord("Bob", "Smith")
	session, _ := newDirSession(t, "me", dirServer{everyone: &bob})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3D100888", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "100888", infoArray[0].Profile.AimID)
	assert.Equal(t, "Bob", infoArray[0].Profile.FirstName)
}

func TestMemberDirHandler_Search_ScreenNameMatchIsFoundForBlankProfile(t *testing.T) {
	// A freshly created account has no directory info at all, and must still be
	// findable by name.
	blank := dirRecord("", "")
	session, _ := newDirSession(t, "me", dirServer{everyone: &blank})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3D100888", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "100888", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_UnknownScreenNameYieldsNothing(t *testing.T) {
	// The identity lookup must not invent a profile for a name nobody holds.
	session, _ := newDirSession(t, "me", dirServer{})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dnobody", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Empty(t, decodeInfoArray(t, rr.Body.Bytes(), true))
}

func TestMemberDirHandler_Search_ScreenNameMatchDoesNotDisplaceInterestResults(t *testing.T) {
	// A keyword that also happens to name a user must return both the interest
	// matches and the identity hit, with any overlap appearing once.
	music := dirRecord("Music", "Fan")
	session, conn := newDirSession(t, "me", dirServer{
		everyone: &music,
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK,
				result("music", "Music", "Fan"), // same user the name lookup finds
				result("OtherFan", "Other", "Fan"),
			)
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dmusic", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 2)
	assert.Equal(t, "music", infoArray[0].Profile.AimID)
	assert.Equal(t, "otherfan", infoArray[1].Profile.AimID)

	queries := sentSearches(conn)
	require.Len(t, queries, 1)
	interest, _ := queries[0].String(wire.ODirTLVInterest)
	assert.Equal(t, "music", interest)
}

func TestMemberDirHandler_Search_ExcludesSelfByScreenName(t *testing.T) {
	// Searching your own UIN must not offer you yourself as a contact.
	me := dirRecord("Me", "Myself")
	session, _ := newDirSession(t, "100777", dirServer{everyone: &me})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3D100777", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Empty(t, decodeInfoArray(t, rr.Body.Bytes(), true))
}

func TestMemberDirHandler_Search_EmailKeywordUsesEmailSearch(t *testing.T) {
	// An address can only be an identifier, and ODir searches email directly, so it
	// must not be sent as an interest.
	session, conn := newDirSession(t, "me", dirServer{
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK, result("BobS", "Bob", "Smith"))
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbob%40example.com", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bobs", infoArray[0].Profile.AimID)

	queries := sentSearches(conn)
	require.Len(t, queries, 1)
	email, ok := queries[0].String(wire.ODirTLVEmailAddress)
	_, isInterest := queries[0].String(wire.ODirTLVInterest)
	assert.True(t, ok)
	assert.Equal(t, "bob@example.com", email)
	assert.False(t, isInterest)
}

// Mandarin escapes each match value before its request builder escapes the whole
// parameter (IcqSearchOptionsBuilder.appendOption + HttpParamsBuilder.build), so
// the query parser leaves one layer on. The web client escapes nothing. Both have
// to arrive as the text the user typed.
func TestParseMatch(t *testing.T) {
	tests := []struct {
		name  string
		match string
		want  map[string]string
	}{
		{
			// What Mandarin sends: the query parser has already removed the outer
			// layer, leaving the values escaped.
			name:  "doubly escaped values are decoded",
			match: "keyword=bob%40example.com,age=19-26,gender=female",
			want:  map[string]string{"keyword": "bob@example.com", "age": "19-26", "gender": "female"},
		},
		{
			// StringUtil.urlEncode writes a space as %20, never '+'.
			name:  "escaped spaces survive",
			match: "firstName=John,lastName=van%20Smith",
			want:  map[string]string{"firstName": "John", "lastName": "van Smith"},
		},
		{
			// An escaped separator must not split the pair, and must come back.
			name:  "escaped separators are not delimiters",
			match: "keyword=rock%2C%20paper",
			want:  map[string]string{"keyword": "rock, paper"},
		},
		{
			// What the web client sends: nothing is escaped, and one pass over an
			// unescaped value changes nothing.
			name:  "unescaped values are untouched",
			match: "firstName=John,lastName=Smith",
			want:  map[string]string{"firstName": "John", "lastName": "Smith"},
		},
		{
			// A '+' is a literal here, not a space. QueryUnescape would eat it.
			name:  "a literal plus is preserved",
			match: "keyword=C++",
			want:  map[string]string{"keyword": "C++"},
		},
		{
			// Not valid escaping, so it is a literal '%' and stays one.
			name:  "an unescapable value is kept verbatim",
			match: "keyword=100% cotton",
			want:  map[string]string{"keyword": "100% cotton"},
		},
		{
			name:  "pairs without a separator are skipped",
			match: "keyword=hi,garbage,=novalue",
			want:  map[string]string{"keyword": "hi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseMatch(tt.match))
		})
	}
}

// An email typed into Mandarin's search box arrives escaped twice. Unless the
// second layer comes off, the keyword holds no literal '@', the email branch of
// buildDirInfoQuery never fires, and the address is searched as an interest.
func TestMemberDirHandler_Search_DoublyEscapedEmailUsesEmailSearch(t *testing.T) {
	session, conn := newDirSession(t, "me", dirServer{
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return searchReply(wire.ODirSearchResponseOK, result("BobS", "Bob", "Smith"))
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	// "keyword=bob%40example.com" with the whole parameter escaped once more.
	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbob%2540example.com", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bobs", infoArray[0].Profile.AimID)

	queries := sentSearches(conn)
	require.Len(t, queries, 1)
	email, ok := queries[0].String(wire.ODirTLVEmailAddress)
	_, isInterest := queries[0].String(wire.ODirTLVInterest)
	assert.True(t, ok)
	assert.Equal(t, "bob@example.com", email)
	assert.False(t, isInterest)
}

func TestMemberDirHandler_Search_ReportsDirectoryFailure(t *testing.T) {
	// The screen name resolves, so a degraded search would have a profile to
	// answer with. A failed directory query is still a failed request.
	bob := dirRecord("Bob", "Smith")
	session, _ := newDirSession(t, "me", dirServer{
		everyone: &bob,
		search: func(wire.SNAC_0x0F_0x02_InfoQuery) wire.SNACMessage {
			return snacErr(wire.ODir, wire.ErrorCodeNotSupportedByHost)
		},
	})
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbobs", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Equal(t, http.StatusInternalServerError, envelopeStatus(t, rr.Body.Bytes()))
	assert.NotContains(t, rr.Body.String(), "infoArray")
}

func TestMemberDirHandler_Search_ReportsScreenNameLookupFailure(t *testing.T) {
	conn := newFakeConn()
	conn.sendErr = io.ErrUnexpectedEOF
	session := newTestSessionAs(t, "me", conn)
	h := &MemberDirHandler{Logger: slog.Default()}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbobs", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	// The lookup runs first, so the directory query is never reached and a
	// search that appears to succeed can never be answered.
	assert.Equal(t, http.StatusInternalServerError, envelopeStatus(t, rr.Body.Bytes()))
	assert.NotContains(t, rr.Body.String(), "infoArray")
}
