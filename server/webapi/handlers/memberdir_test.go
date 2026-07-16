package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

type mockDirSearchService struct{ mock.Mock }

func (m *mockDirSearchService) InfoQuery(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0F_0x02_InfoQuery) (wire.SNACMessage, error) {
	args := m.Called(ctx, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

type mockMemberDirLocateService struct{ mock.Mock }

func (m *mockMemberDirLocateService) DirInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error) {
	args := m.Called(ctx, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func (m *mockMemberDirLocateService) SetDirInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x09_LocateSetDirInfo) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

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

func TestMemberDirHandler_Search_Keyword(t *testing.T) {
	dirSvc := &mockDirSearchService{}
	// keyword=haha must map to the ODir interest TLV.
	dirSvc.On("InfoQuery", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		v, ok := q.String(wire.ODirTLVInterest)
		return ok && v == "haha"
	})).Return(searchReply(wire.ODirSearchResponseOK, result("FoundUser", "Found", "User")), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dhaha&nToGet=200", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "founduser", infoArray[0].Profile.AimID)
	assert.Equal(t, "FoundUser", infoArray[0].Profile.DisplayID)
	assert.Equal(t, "Found", infoArray[0].Profile.FirstName)
	dirSvc.AssertExpectations(t)
}

func TestMemberDirHandler_Search_FirstLastName(t *testing.T) {
	dirSvc := &mockDirSearchService{}
	// firstName/lastName must map to the ODir name TLVs, not interest.
	dirSvc.On("InfoQuery", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x0F_0x02_InfoQuery) bool {
		first, hasFirst := q.String(wire.ODirTLVFirstName)
		last, hasLast := q.String(wire.ODirTLVLastName)
		_, hasInterest := q.String(wire.ODirTLVInterest)
		return hasFirst && first == "Bob" && hasLast && last == "Smith" && !hasInterest
	})).Return(searchReply(wire.ODirSearchResponseOK, result("Bob", "Bob", "Smith")), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=firstName%3DBob%2ClastName%3DSmith", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bob", infoArray[0].Profile.AimID)
	dirSvc.AssertExpectations(t)
}

func TestMemberDirHandler_Search_ExcludesSelf(t *testing.T) {
	dirSvc := &mockDirSearchService{}
	dirSvc.On("InfoQuery", mock.Anything, mock.Anything, mock.Anything).Return(
		searchReply(wire.ODirSearchResponseOK,
			result("Me", "", ""),    // caller — must be filtered out
			result("Other", "", ""), // kept
		), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("M E")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dx", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), true)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "other", infoArray[0].Profile.AimID)
}

func TestMemberDirHandler_Search_RespectsJSONPCallback(t *testing.T) {
	dirSvc := &mockDirSearchService{}
	dirSvc.On("InfoQuery", mock.Anything, mock.Anything, mock.Anything).Return(
		searchReply(wire.ODirSearchResponseOK), nil)

	h := &MemberDirHandler{DirSearchService: dirSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	req := httptest.NewRequest("GET", "/memberDir/search?aimsid=sid&match=keyword%3Dx&c=_callbacks_._abc", nil)
	rr := httptest.NewRecorder()
	h.Search(rr, req, session)

	// The web client loads this via a <script> tag, so the response must be
	// JavaScript (JSONP), not application/json — otherwise the browser CORB-blocks it.
	assert.Equal(t, "application/javascript", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "_callbacks_._abc(")
}

func TestMemberDirHandler_Get_Self(t *testing.T) {
	reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, "Me"))
	reply.Append(wire.NewTLVBE(wire.ODirTLVLastName, "Myself"))

	locSvc := &mockMemberDirLocateService{}
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "me"
	})).Return(wire.SNACMessage{Body: reply}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

	// No "t" param: defaults to self.
	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "me", infoArray[0].Profile.AimID)
	assert.Equal(t, "Me", infoArray[0].Profile.FirstName)
	assert.Equal(t, "Myself", infoArray[0].Profile.LastName)
	locSvc.AssertExpectations(t)
}

func TestMemberDirHandler_Get_LabelsEachTargetWithOwnIdentity(t *testing.T) {
	dirReply := func(firstName string) wire.SNACMessage {
		reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
		reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, firstName))
		return wire.SNACMessage{Body: reply}
	}

	locSvc := &mockMemberDirLocateService{}
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "Bob Smith"
	})).Return(dirReply("Bob"), nil)
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "alice"
	})).Return(dirReply("Alice"), nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("Bob Smith")}

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
	locSvc.AssertExpectations(t)
}

func TestMemberDirHandler_Get_CapsTargetFanOut(t *testing.T) {
	locSvc := &mockMemberDirLocateService{}
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("me")}

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
	locSvc.AssertNumberOfCalls(t, "DirInfo", maxMemberDirTargets)
}

func TestMemberDirHandler_Update_PersistsNameAndPreservesOtherFields(t *testing.T) {
	// Current directory record has a city set that the name form must not wipe.
	current := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	current.Append(wire.NewTLVBE(wire.ODirTLVFirstName, "Old"))
	current.Append(wire.NewTLVBE(wire.ODirTLVLastName, "Name"))
	current.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	locSvc := &mockMemberDirLocateService{}
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: current}, nil)
	// The set request must carry the new name AND the preserved city.
	locSvc.On("SetDirInfo", mock.Anything, mock.Anything, mock.Anything,
		mock.MatchedBy(func(b wire.SNAC_0x02_0x09_LocateSetDirInfo) bool {
			first, _ := b.String(wire.ODirTLVFirstName)
			last, _ := b.String(wire.ODirTLVLastName)
			city, _ := b.String(wire.ODirTLVCity)
			return first == "Mike" && last == "K" && city == "Reno"
		})).Return(wire.SNACMessage{}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

	req := httptest.NewRequest("GET",
		"/memberDir/update?aimsid=sid&set=firstName%3DMike&set=lastName%3DK&set=hideLevel%3DemailsAndCellular", nil)
	rr := httptest.NewRecorder()
	h.Update(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	locSvc.AssertExpectations(t)
}

func TestMemberDirHandler_Update_AbortsWhenCurrentInfoUnreadable(t *testing.T) {
	locSvc := &mockMemberDirLocateService{}
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{}, io.ErrUnexpectedEOF)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("mike")}

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
