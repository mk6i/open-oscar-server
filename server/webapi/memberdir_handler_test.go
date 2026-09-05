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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func searchReply(status uint16, results ...wire.TLVBlock) wire.SNACMessage {
	body := wire.SNAC_0x0F_0x03_InfoReply{Status: status}
	body.Results.List = results
	return wire.SNACMessage{Body: body}
}

func result(screenName, firstName, lastName string) wire.TLVBlock {
	return wire.TLVBlock{TLVList: wire.TLVList{
		wire.NewTLVBE(wire.ODirTLVScreenName, screenName),
		wire.NewTLVBE(wire.ODirTLVFirstName, firstName),
		wire.NewTLVBE(wire.ODirTLVLastName, lastName),
	}}
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

// stubNoDirUser answers DirInfo with no directory TLVs, which is what the service
// returns for a name that belongs to no user. Every search test needs one, since
// Search does an identity lookup alongside the directory query.
func stubNoDirUser(t *testing.T) *mockLocateService {
	ls := newMockLocateService(t)
	ls.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
			Status: wire.LocateGetDirReplyOK,
		}}, nil).Maybe()
	return ls
}

func TestMemberDirHandler_Search_Keyword(t *testing.T) {
	dirSvc := newMockDirSearchService(t)
	// keyword=haha must map to the ODir interest TLV.
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		v, ok := q.String(wire.ODirTLVInterest)
		return ok && v == "haha"
	})).Return(searchReply(wire.ODirSearchResponseOK, result("FoundUser", "Found", "User")), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, LocateService: stubNoDirUser(t), Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dhaha&nToGet=200", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "founduser", infoArray[0].Profile.AimID)
	assert.Equal(t, "FoundUser", infoArray[0].Profile.DisplayID)
	assert.Equal(t, "Found", infoArray[0].Profile.FirstName)
}

func TestMemberDirHandler_Search_FirstLastName(t *testing.T) {
	dirSvc := newMockDirSearchService(t)
	// firstName/lastName must map to the ODir name TLVs, not interest.
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		first, hasFirst := q.String(wire.ODirTLVFirstName)
		last, hasLast := q.String(wire.ODirTLVLastName)
		_, hasInterest := q.String(wire.ODirTLVInterest)
		return hasFirst && first == "Bob" && hasLast && last == "Smith" && !hasInterest
	})).Return(searchReply(wire.ODirSearchResponseOK, result("Bob", "Bob", "Smith")), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, LocateService: stubNoDirUser(t), Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=firstName%3DBob%2ClastName%3DSmith", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bob", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_ExcludesSelf(t *testing.T) {
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).Return(
		searchReply(wire.ODirSearchResponseOK,
			result("Me", "", ""),    // caller — must be filtered out
			result("Other", "", ""), // kept
		), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, LocateService: stubNoDirUser(t), Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("M E")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dx", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "other", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_RespectsJSONPCallback(t *testing.T) {
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).Return(
		searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, LocateService: stubNoDirUser(t), Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

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
	reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, "Me"))
	reply.Append(wire.NewTLVBE(wire.ODirTLVLastName, "Myself"))

	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "me"
	})).Return(wire.SNACMessage{Body: reply}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	// No "t" param: defaults to self.
	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "me", infoArray[0].Profile.AimID)
	assert.Equal(t, "Me", infoArray[0].Profile.FirstName)
	assert.Equal(t, "Myself", infoArray[0].Profile.LastName)
}

func TestMemberDirHandler_Get_LabelsEachTargetWithOwnIdentity(t *testing.T) {
	dirReply := func(firstName string) wire.SNACMessage {
		reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
		reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, firstName))
		return wire.SNACMessage{Body: reply}
	}

	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "Bob Smith"
	})).Return(dirReply("Bob"), nil)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "alice"
	})).Return(dirReply("Alice"), nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("Bob Smith")}

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
	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}}, nil).
		Times(maxMemberDirTargets)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

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
}

func TestMemberDirHandler_Update_PersistsNameAndPreservesOtherFields(t *testing.T) {
	// Current directory record has a city set that the name form must not wipe.
	current := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	current.Append(wire.NewTLVBE(wire.ODirTLVFirstName, "Old"))
	current.Append(wire.NewTLVBE(wire.ODirTLVLastName, "Name"))
	current.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: current}, nil)
	// The set request must carry the new name AND the preserved city.
	locSvc.EXPECT().SetDirInfo(mock.Anything, mock.Anything, mock.Anything,
		mock.MatchedBy(func(b wire.SNAC_0x02_0x09_LocateSetDirInfo) bool {
			first, _ := b.String(wire.ODirTLVFirstName)
			last, _ := b.String(wire.ODirTLVLastName)
			city, _ := b.String(wire.ODirTLVCity)
			return first == "Mike" && last == "K" && city == "Reno"
		})).Return(wire.SNACMessage{}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

	req := httptest.NewRequest("GET",
		"/memberDir/update?aimsid=sid&set=firstName%3DMike&set=lastName%3DK&set=hideLevel%3DemailsAndCellular", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestMemberDirHandler_Update_AbortsWhenCurrentInfoUnreadable(t *testing.T) {
	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, io.ErrUnexpectedEOF)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

	req := httptest.NewRequest("GET", "/memberDir/update?aimsid=sid&set=firstName%3DMike&set=lastName%3DK", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	// SetDirectoryInfo replaces every column, so writing a record we couldn't
	// seed would blank the fields this form doesn't edit. Report the failure
	// instead.
	locSvc.AssertNotCalled(t, "SetDirInfo", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	var envelope struct {
		Response struct {
			StatusCode int `json:"statusCode"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, http.StatusInternalServerError, envelope.Response.StatusCode)
}

func TestMemberDirHandler_Update_ReadsDoubleEncodedFormBody(t *testing.T) {
	// A form body encodes each "set" value twice — once building the pair, once
	// building the body — and arrives with no Content-Type, which is what
	// parseBodyForm's defaulting exists to handle.
	current := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	current.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: current}, nil)
	locSvc.EXPECT().SetDirInfo(mock.Anything, mock.Anything, mock.Anything,
		mock.MatchedBy(func(b wire.SNAC_0x02_0x09_LocateSetDirInfo) bool {
			first, _ := b.String(wire.ODirTLVFirstName)
			last, _ := b.String(wire.ODirTLVLastName)
			city, _ := b.String(wire.ODirTLVCity)
			// Without the second unescape these arrive as "Bob%20Smith" and
			// "O%27Brien" and are stored verbatim.
			return first == "Bob Smith" && last == "O'Brien" && city == "Reno"
		})).Return(wire.SNACMessage{}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

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
}

func TestMemberDirHandler_Update_QueryValuesAreNotUnescapedTwice(t *testing.T) {
	// Query values are encoded once and are final after the query decoder runs.
	// Unescaping again would corrupt a name carrying a literal '%'.
	current := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}

	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: current}, nil)
	locSvc.EXPECT().SetDirInfo(mock.Anything, mock.Anything, mock.Anything,
		mock.MatchedBy(func(b wire.SNAC_0x02_0x09_LocateSetDirInfo) bool {
			first, _ := b.String(wire.ODirTLVFirstName)
			last, _ := b.String(wire.ODirTLVLastName)
			return first == "100%" && last == "Smith"
		})).Return(wire.SNACMessage{}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

	req := httptest.NewRequest("GET",
		"/memberDir/update?aimsid=sid&set=firstName%3D100%25&set=lastName%3DSmith", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
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

// dirUser answers DirInfo as an existing user. The service appends directory TLVs
// only for a user that exists, so their presence marks the name as found.
func dirUser(t *testing.T, firstName, lastName string) *mockLocateService {
	reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, firstName))
	reply.Append(wire.NewTLVBE(wire.ODirTLVLastName, lastName))
	ls := newMockLocateService(t)
	ls.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: reply}, nil).Maybe()
	return ls
}

func TestMemberDirHandler_Search_MatchesScreenName(t *testing.T) {
	// An add-contact box that takes an email or UIN sends the value as keyword, but
	// ODir searches interests, names and email — never the screen name.
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).
		Return(searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    dirUser(t, "Bob", "Smith"),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

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
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).
		Return(searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    dirUser(t, "", ""),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3D100888", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "100888", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_UnknownScreenNameYieldsNothing(t *testing.T) {
	// The identity lookup must not invent a profile for a name nobody holds.
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).
		Return(searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    stubNoDirUser(t),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dnobody", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Empty(t, decodeInfoArray(t, rr.Body.Bytes(), true))
}

func TestMemberDirHandler_Search_ScreenNameMatchDoesNotDisplaceInterestResults(t *testing.T) {
	// A keyword that also happens to name a user must return both the interest
	// matches and the identity hit, with any overlap appearing once.
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		v, ok := q.String(wire.ODirTLVInterest)
		return ok && v == "music"
	})).Return(searchReply(wire.ODirSearchResponseOK,
		result("music", "Music", "Fan"), // same user the name lookup finds
		result("OtherFan", "Other", "Fan"),
	), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    dirUser(t, "Music", "Fan"),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dmusic", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 2)
	assert.Equal(t, "music", infoArray[0].Profile.AimID)
	assert.Equal(t, "otherfan", infoArray[1].Profile.AimID)
}

func TestMemberDirHandler_Search_ExcludesSelfByScreenName(t *testing.T) {
	// Searching your own UIN must not offer you yourself as a contact.
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).
		Return(searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    dirUser(t, "Me", "Myself"),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("100777")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3D100777", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Empty(t, decodeInfoArray(t, rr.Body.Bytes(), true))
}

func TestMemberDirHandler_Search_EmailKeywordUsesEmailSearch(t *testing.T) {
	// An address can only be an identifier, and ODir searches email directly, so it
	// must not be sent as an interest.
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		v, ok := q.String(wire.ODirTLVEmailAddress)
		_, isInterest := q.String(wire.ODirTLVInterest)
		return ok && v == "bob@example.com" && !isInterest
	})).Return(searchReply(wire.ODirSearchResponseOK, result("BobS", "Bob", "Smith")), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    stubNoDirUser(t),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbob%40example.com", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bobs", infoArray[0].Profile.AimID)
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
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		v, ok := q.String(wire.ODirTLVEmailAddress)
		_, isInterest := q.String(wire.ODirTLVInterest)
		return ok && v == "bob@example.com" && !isInterest
	})).Return(searchReply(wire.ODirSearchResponseOK, result("BobS", "Bob", "Smith")), nil)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		LocateService:    stubNoDirUser(t),
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	// "keyword=bob%40example.com" with the whole parameter escaped once more.
	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbob%2540example.com", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bobs", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_ReportsDirectoryFailure(t *testing.T) {
	dirSvc := newMockDirSearchService(t)
	dirSvc.EXPECT().InfoQuery(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, io.ErrUnexpectedEOF)

	h := &MemberDirHandler{
		DirSearchService: dirSvc,
		// The screen name resolves, so a degraded search would have a profile to
		// answer with. A failed directory query is still a failed request.
		LocateService: dirUser(t, "Bob", "Smith"),
		Logger:        slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbobs", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	var envelope struct {
		Response struct {
			StatusCode int `json:"statusCode"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, http.StatusInternalServerError, envelope.Response.StatusCode)
	assert.NotContains(t, rr.Body.String(), "infoArray")
}

func TestMemberDirHandler_Search_ReportsScreenNameLookupFailure(t *testing.T) {
	locSvc := newMockLocateService(t)
	locSvc.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, io.ErrUnexpectedEOF)

	h := &MemberDirHandler{
		// No expectation: the lookup runs first, so the directory query is never
		// reached and a search that appears to succeed can never be answered.
		DirSearchService: newMockDirSearchService(t),
		LocateService:    locSvc,
		Logger:           slog.Default(),
	}
	session := &Session{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dbobs", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	var envelope struct {
		Response struct {
			StatusCode int `json:"statusCode"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, http.StatusInternalServerError, envelope.Response.StatusCode)
	assert.NotContains(t, rr.Body.String(), "infoArray")
}
