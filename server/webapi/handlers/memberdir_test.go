package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestMemberDirHandler_Get_UsesSessionDisplayName(t *testing.T) {
	locSvc := &mockMemberDirLocateService{}
	// Client requests its own record by normalized name...
	locSvc.On("DirInfo", mock.Anything, mock.Anything, mock.MatchedBy(func(q wire.SNAC_0x02_0x0B_LocateGetDirInfo) bool {
		return q.ScreenName == "bobsmith"
	})).Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}}, nil)

	h := &MemberDirHandler{LocateService: locSvc, Logger: slog.Default()}
	// ...but the session carries the formatted display name.
	session := &state.WebAPISession{AimSID: "sid", ScreenName: state.DisplayScreenName("Bob Smith")}

	req := httptest.NewRequest("GET", "/memberDir/get?aimsid=sid&t=bobsmith", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req, session)

	infoArray := decodeInfoArray(t, rr.Body.Bytes(), false)
	require.Len(t, infoArray, 1)
	assert.Equal(t, "bobsmith", infoArray[0].Profile.AimID)
	// displayId is the session's formatted name, not the raw "t" value.
	assert.Equal(t, "Bob Smith", infoArray[0].Profile.DisplayID)
	locSvc.AssertExpectations(t)
}
