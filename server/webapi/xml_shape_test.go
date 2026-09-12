package webapi

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
)

// renderXML sends payload through the f=xml path and returns the body.
func renderXML(t *testing.T, data any) string {
	t.Helper()
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	resp.Response.RequestID = "123"
	resp.Response.Data = data

	rr := httptest.NewRecorder()
	SendResponse(rr, httptest.NewRequest(http.MethodGet, "/x?f=xml&r=123", nil), resp, nil)

	body := rr.Body.String()
	require.Contains(t, rr.Header().Get("Content-Type"), "xml")
	// A document the client could not parse is the failure this guards against.
	var probe any
	require.NoError(t, xml.Unmarshal([]byte(body), &probe), "not well-formed: %s", body)
	return body
}

// The spec renders the envelope as a flat <response> root carrying statusCode,
// statusText, requestId and data — not the "response"-keyed nesting JSON uses.
func TestXMLEnvelopeMatchesSpec(t *testing.T) {
	body := renderXML(t, struct {
		AimSID string `xml:"aimsid"`
	}{AimSID: "opaquedata"})

	assert.Contains(t, body, `<?xml version="1.0" encoding="UTF-8"?>`)
	assert.Contains(t, body, "<response><statusCode>200</statusCode><statusText>Ok</statusText>"+
		"<requestId>123</requestId><data><aimsid>opaquedata</aimsid></data></response>")
}

// Every method in the spec renders a data element even when it carries no
// payload; the client dereferences response.data regardless of outcome.
func TestXMLAlwaysRendersData(t *testing.T) {
	rr := httptest.NewRecorder()
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	SendResponse(rr, httptest.NewRequest(http.MethodGet, "/aim/endSession?f=xml", nil), resp, nil)

	assert.Contains(t, rr.Body.String(), "<data></data>")
}

// The item names inside a list element are fixed by the spec and cannot be
// derived from the container's name (allows holds allow, not user).
func TestXMLItemNamesMatchSpec(t *testing.T) {
	t.Run("buddy list", func(t *testing.T) {
		body := renderXML(t, &BuddyListData{Groups: []BuddyGroup{{
			Name: "Friends",
			Buddies: []BuddyInfo{{
				AimID:        "chattingchuck",
				DisplayID:    "ChattingChuck",
				State:        "away",
				UserType:     "aim",
				Capabilities: []string{"200A0000A28911D3A52D001083341CFA"},
			}},
		}}})

		assert.Contains(t, body, "<groups><group><name>Friends</name>")
		assert.Contains(t, body, "<buddies><buddy><aimId>chattingchuck</aimId>")
		assert.Contains(t, body, "<capabilities><capability>200A0000A28911D3A52D001083341CFA</capability></capabilities>")
		// The Go field names must not leak through as element names.
		assert.NotContains(t, body, "<AimID>")
		assert.NotContains(t, body, "<Buddies>")
	})

	t.Run("permit deny", func(t *testing.T) {
		body := renderXML(t, PermitDenyData{
			PDMode:     "permitOnList",
			PermitList: []string{"ChattingChuck"},
			DenyList:   []string{"fred"},
		})

		assert.Contains(t, body, "<pdMode>permitOnList</pdMode>")
		assert.Contains(t, body, "<allows><allow>ChattingChuck</allow></allows>")
		assert.Contains(t, body, "<blocks><block>fred</block></blocks>")
	})

	t.Run("presence", func(t *testing.T) {
		body := renderXML(t, PresenceData{Users: []BuddyPresenceInfo{{
			AimID: "chattingchuck", State: "away", UserType: "aim",
		}}})

		assert.Contains(t, body, "<users><user><aimId>chattingchuck</aimId>")
	})

	t.Run("fetch events", func(t *testing.T) {
		body := renderXML(t, &FetchEventsData{
			Events: []Event{{
				Type:      EventTypeTyping,
				SeqNum:    7,
				Timestamp: 100,
				Data:      TypingEvent{AimID: "chattingchuck", TypingStatus: "typing"},
			}},
			LastSeqNum: 7,
		})

		assert.Contains(t, body, "<events><event><type>typing</type><seqNum>7</seqNum>")
		assert.Contains(t, body, "<eventData><aimId>chattingchuck</aimId><typingStatus>typing</typingStatus></eventData>")
	})
}

// myInfo is the payload the spec documents in the most detail, and the one the
// old hand-built XML truncated to two fields.
func TestXMLMyInfoCarriesEveryField(t *testing.T) {
	mi := buildMyInfo(state.DisplayScreenName("ChattingChuck"), "away", "http://host/icon", "")
	mi.OnlineTime = 100
	mi.AwayMsg = "I'm busy right now chatting."

	body := renderXML(t, mi)

	for _, want := range []string{
		"<aimId>chattingchuck</aimId>",
		"<displayId>ChattingChuck</displayId>",
		"<friendly>ChattingChuck</friendly>",
		"<state>away</state>",
		"<userType>aim</userType>",
		"<awayMsg>I&#39;m busy right now chatting.</awayMsg>",
		"<buddyIcon>http://host/icon</buddyIcon>",
		"<onlineTime>100</onlineTime>",
	} {
		assert.Contains(t, body, want)
	}
}

// Preferences are the one payload that is legitimately partial, so an absent
// preference and one set to zero have to stay distinguishable in XML too.
func TestXMLPreferencesDistinguishAbsentFromZero(t *testing.T) {
	prefs := &PreferenceData{}
	prefs.Set("showGroups", 0)

	body := renderXML(t, prefs)

	assert.Contains(t, body, "<showGroups>0</showGroups>")
	assert.NotContains(t, body, "<playIMSound>")
}
