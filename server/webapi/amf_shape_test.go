package webapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	goAMF3 "github.com/breign/goAMF3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeAMF decodes an AMF3 body as the object every Web API reply is.
func decodeAMF(t *testing.T, body []byte) map[string]any {
	t.Helper()
	decoded := goAMF3.DecodeAMF3(body)
	m, ok := decoded.(map[string]any)
	require.True(t, ok, "decoded as %T, want an object", decoded)
	return m
}

// renderAMF sends payload through the f=amf3 path and returns the response body.
func renderAMF(t *testing.T, data any) map[string]any {
	t.Helper()
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	resp.Response.Data = data

	rr := httptest.NewRecorder()
	SendResponse(rr, httptest.NewRequest(http.MethodGet, "/x?f=amf3&r=123", nil), resp, nil)
	require.Contains(t, rr.Header().Get("Content-Type"), "amf")

	envelope := decodeAMF(t, rr.Body.Bytes())
	body, ok := envelope["response"].(map[string]any)
	require.True(t, ok, "response = %#v, want an object", envelope["response"])
	return body
}

// object asserts that key holds a nested AMF3 object and returns it.
func object(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	require.True(t, ok, "%s = %#v, want an object", key, m[key])
	return v
}

// firstEvent returns the single event a fetchEvents payload carries.
func firstEvent(t *testing.T, event Event) (map[string]any, map[string]any) {
	t.Helper()
	body := renderAMF(t, &FetchEventsData{Events: []Event{event}, LastSeqNum: event.SeqNum})

	events, ok := object(t, body, "data")["events"].([]any)
	require.True(t, ok, "events is not an array")
	require.Len(t, events, 1)

	wrapper, ok := events[0].(map[string]any)
	require.True(t, ok, "events[0] = %#v, want an object", events[0])
	return wrapper, object(t, wrapper, "eventData")
}

// The envelope nests the body under "response", where XML flattens it to the
// document root.
func TestAMFEnvelopeMatchesSpec(t *testing.T) {
	body := renderAMF(t, struct {
		AimSID string `json:"aimsid"`
	}{AimSID: "opaquedata"})

	assert.Equal(t, int32(200), body["statusCode"])
	assert.Equal(t, "Ok", body["statusText"])
	assert.Equal(t, "123", body["requestId"])
	assert.Equal(t, map[string]any{"aimsid": "opaquedata"}, object(t, body, "data"))
}

// Every method sends a data object even when it carries no payload; the client
// dereferences response.data regardless of outcome.
func TestAMFAlwaysRendersData(t *testing.T) {
	rr := httptest.NewRecorder()
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	SendResponse(rr, httptest.NewRequest(http.MethodGet, "/aim/endSession?f=amf3", nil), resp, nil)

	body := object(t, decodeAMF(t, rr.Body.Bytes()), "response")
	assert.Equal(t, map[string]any{}, object(t, body, "data"))
}

// A failure carries the same envelope, including the data object a client
// callback reaches for on any outcome.
func TestAMFErrorEnvelope(t *testing.T) {
	rr := httptest.NewRecorder()
	SendErrorDetail(rr, httptest.NewRequest(http.MethodGet, "/x?f=amf3&r=123", nil),
		http.StatusUnauthorized, statusMoreAuthRequired, detailBadPassword, "invalid password")

	body := object(t, decodeAMF(t, rr.Body.Bytes()), "response")
	assert.Equal(t, int32(statusMoreAuthRequired), body["statusCode"])
	assert.Equal(t, int32(detailBadPassword), body["statusDetailCode"])
	assert.Equal(t, "invalid password", body["statusText"])
	assert.Equal(t, "123", body["requestId"])
	assert.Equal(t, map[string]any{}, object(t, body, "data"))
}

// AMF3 stores whole numbers in 29 bits, which a Unix timestamp overflows, so
// every time value has to reach the client as a double.
func TestAMFTimestampsAreDoubles(t *testing.T) {
	wrapper, eventData := firstEvent(t, Event{
		Type:      EventTypeIM,
		SeqNum:    7,
		Timestamp: 1700000000,
		Data: IMEvent{
			Source:    UserInfo{AimID: "chattingchuck", OnlineTime: 1699999000},
			Message:   "hi",
			Timestamp: 1700000000,
		},
	})

	assert.Equal(t, float64(1700000000), wrapper["timestamp"])
	assert.Equal(t, float64(1700000000), eventData["timestamp"])
	assert.Equal(t, float64(1699999000), object(t, eventData, "source")["onlineTime"])
	// A sequence number is small enough to stay a compact AMF3 integer.
	assert.Equal(t, int32(7), wrapper["seqNum"])
}

// myInfo carries the timestamps most likely to overflow, and reaches the encoder
// as a struct rather than a map.
func TestAMFMyInfoTimestampsAreDoubles(t *testing.T) {
	mi := buildMyInfo("ChattingChuck", "online", "")
	mi.OnlineTime = 1700000000
	mi.MemberSince = 1500000000
	mi.Self = &MyInfoSelf{InstNum: 1, LoginTime: 1700000001, Events: []string{}, AssertCaps: []string{}}

	body := renderAMF(t, mi)
	data := object(t, body, "data")

	assert.Equal(t, float64(1700000000), data["onlineTime"])
	assert.Equal(t, float64(1500000000), data["memberSince"])
	assert.Equal(t, float64(1700000001), object(t, data, "self")["loginTime"])
	// A list the client iterates unconditionally is sent even when empty.
	assert.Equal(t, []any{}, data["capabilities"])
}

// The client reads the sender of a sentIM from "source" and the flag from
// "autoresponse", which is not how the JSON spec names either one.
func TestAMFSentIMUsesClientFieldNames(t *testing.T) {
	_, eventData := firstEvent(t, Event{
		Type:   EventTypeSentIM,
		SeqNum: 1,
		Data: SentIMEvent{
			Sender:  UserInfo{AimID: "chattingchuck", DisplayID: "ChattingChuck", UserType: "aim", State: "online"},
			Dest:    UserInfo{AimID: "fred", DisplayID: "Fred", Friendly: "Freddy", UserType: "aim", State: "online"},
			Message: "hi",
			MsgID:   "beefcafe",
		},
	})

	source := object(t, eventData, "source")
	assert.Equal(t, "chattingchuck", source["aimId"])
	assert.Equal(t, "online", source["state"])
	assert.NotContains(t, eventData, "sender")

	dest := object(t, eventData, "dest")
	assert.Equal(t, "fred", dest["aimId"])
	// The client's merge deletes any alias it holds before applying a user map,
	// so an alias has to be repeated on every one.
	assert.Equal(t, "Freddy", dest["friendly"])

	assert.Equal(t, "beefcafe", eventData["msgId"])
	// Always sent, false included, and never under the JSON spelling.
	assert.Equal(t, false, eventData["autoresponse"])
	assert.NotContains(t, eventData, "autoResponse")
}

// Presence is the whole user object the client's parseUser reads, not a subset.
func TestAMFPresenceCarriesEveryField(t *testing.T) {
	_, eventData := firstEvent(t, Event{
		Type:   EventTypePresence,
		SeqNum: 1,
		Data: PresenceEvent{
			AimID:      "mikekelly",
			Friendly:   "Mike",
			State:      "away",
			StatusMsg:  "at lunch",
			AwayMsg:    "back soon",
			IdleTime:   5,
			OnlineTime: 1700000000,
			UserType:   "aim",
			BuddyIcon:  "http://host/icon",
		},
	})

	assert.Equal(t, "mikekelly", eventData["aimId"])
	assert.Equal(t, "Mike", eventData["friendly"])
	assert.Equal(t, "away", eventData["state"])
	assert.Equal(t, "at lunch", eventData["statusMsg"])
	assert.Equal(t, "back soon", eventData["awayMsg"])
	assert.Equal(t, int32(5), eventData["idleTime"])
	assert.Equal(t, float64(1700000000), eventData["onlineTime"])
	assert.Equal(t, "aim", eventData["userType"])
	assert.Equal(t, "http://host/icon", eventData["buddyIcon"])
}

// An empty buddyIcon is left out so the client's merge keeps the icon it holds;
// the placeholder URL, not "", is what clears one.
func TestAMFPresenceOmitsEmptyBuddyIcon(t *testing.T) {
	_, eventData := firstEvent(t, Event{
		Type:   EventTypePresence,
		SeqNum: 1,
		Data:   PresenceEvent{AimID: "mikekelly", State: "offline", UserType: "aim"},
	})

	assert.NotContains(t, eventData, "buddyIcon")
}

// An offline sender is identified by aimId and friendly alone, and the client
// keys its conversation list by msgId.
func TestAMFOfflineIM(t *testing.T) {
	_, eventData := firstEvent(t, Event{
		Type:   EventTypeOfflineIM,
		SeqNum: 1,
		Data: OfflineIMEvent{
			AimID:     "mikekelly",
			Friendly:  "Mike Kelly",
			Message:   "sent while you were out",
			MsgID:     "beefcafe",
			Timestamp: 1700000000,
		},
	})

	assert.Equal(t, "mikekelly", eventData["aimId"])
	assert.Equal(t, "Mike Kelly", eventData["friendly"])
	assert.Equal(t, "sent while you were out", eventData["message"])
	assert.Equal(t, "beefcafe", eventData["msgId"])
	assert.Equal(t, float64(1700000000), eventData["timestamp"])
	assert.Equal(t, false, eventData["autoresponse"])
}

// A payload of nested structs and lists survives whole; the AMF3 writer emits
// nothing for a value it cannot take, truncating the object mid-key.
func TestAMFNestedPayloadSurvives(t *testing.T) {
	_, eventData := firstEvent(t, Event{
		Type:   EventTypeBuddyList,
		SeqNum: 1,
		Data: &BuddyListData{Groups: []BuddyGroup{{
			Name: "Friends",
			Buddies: []BuddyInfo{{
				AimID:        "chattingchuck",
				DisplayID:    "ChattingChuck",
				Capabilities: []string{"200A0000A28911D3A52D001083341CFA"},
			}},
		}}},
	})

	groups, ok := eventData["groups"].([]any)
	require.True(t, ok, "groups = %#v, want an array", eventData["groups"])
	require.Len(t, groups, 1)

	group, ok := groups[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Friends", group["name"])

	buddies, ok := group["buddies"].([]any)
	require.True(t, ok)
	require.Len(t, buddies, 1)

	buddy, ok := buddies[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "chattingchuck", buddy["aimId"])
	assert.Equal(t, []any{"200A0000A28911D3A52D001083341CFA"}, buddy["capabilities"])
}

// A typed nil payload is an empty object rather than a truncated stream.
func TestAMFNilEventDataIsAnObject(t *testing.T) {
	wrapper, _ := firstEvent(t, Event{
		Type:   EventTypeBuddyList,
		SeqNum: 3,
		Data:   (*BuddyListData)(nil),
	})

	assert.Equal(t, int32(3), wrapper["seqNum"])
}
