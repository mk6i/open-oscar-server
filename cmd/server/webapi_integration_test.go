package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// webAPIEvent is one event from aim/fetchEvents.
type webAPIEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"eventData"`
}

// webAPITestClient is a Web AIM client of the WebAPI server under test.
type webAPITestClient struct {
	t       *testing.T
	name    string
	baseURL string
	aimsid  string
	seqNum  uint64
	// startEvents are the events in the startSession response.
	startEvents json.RawMessage
}

// webAPIResponse is the Web API response envelope.
type webAPIResponse struct {
	Response struct {
		StatusCode int             `json:"statusCode"`
		StatusText string          `json:"statusText"`
		Data       json.RawMessage `json:"data"`
	} `json:"response"`
}

// call sends a Web API request and returns the envelope's status code and data.
func (c *webAPITestClient) call(method string, path string, params url.Values) (int, json.RawMessage) {
	params.Set("f", "json")
	var (
		resp *http.Response
		err  error
	)
	if method == http.MethodPost {
		resp, err = http.PostForm(c.baseURL+path, params)
	} else {
		resp, err = http.Get(c.baseURL + path + "?" + params.Encode())
	}
	if !assert.NoError(c.t, err) {
		c.t.FailNow()
	}
	defer func() { _ = resp.Body.Close() }()

	envelope := webAPIResponse{}
	if !assert.NoError(c.t, json.NewDecoder(resp.Body).Decode(&envelope), "%s %s", method, path) {
		c.t.FailNow()
	}
	return envelope.Response.StatusCode, envelope.Response.Data
}

// session sends a request on behalf of the client's session.
func (c *webAPITestClient) session(path string, params url.Values) (int, json.RawMessage) {
	params.Set("aimsid", c.aimsid)
	return c.call(http.MethodGet, path, params)
}

// startWebAPISession signs screenName on through clientLogin and
// startSession, subscribing to events.
func startWebAPISession(t *testing.T, baseURL string, screenName string, events string) *webAPITestClient {
	c := &webAPITestClient{t: t, name: screenName, baseURL: baseURL}

	status, data := c.call(http.MethodPost, "/auth/clientLogin", url.Values{
		"s":   {screenName},
		"pwd": {"password"},
	})
	if !assert.Equal(t, http.StatusOK, status, "clientLogin") {
		t.FailNow()
	}
	login := struct {
		Token struct {
			A string `json:"a"`
		} `json:"token"`
	}{}
	assert.NoError(t, json.Unmarshal(data, &login))

	status, data = c.call(http.MethodGet, "/aim/startSession", url.Values{
		"a":      {login.Token.A},
		"events": {events},
	})
	if !assert.Equal(t, http.StatusOK, status, "startSession") {
		t.FailNow()
	}
	start := struct {
		AimSID string          `json:"aimsid"`
		Events json.RawMessage `json:"events"`
	}{}
	assert.NoError(t, json.Unmarshal(data, &start))
	c.aimsid = start.AimSID
	c.startEvents = start.Events
	return c
}

// buddyState returns the state of buddy in the buddylist event of events, or
// "" if it lists no such buddy.
func buddyState(events json.RawMessage, buddy string) string {
	var payload struct {
		BuddyList struct {
			Groups []struct {
				Buddies []struct {
					AimID string `json:"aimId"`
					State string `json:"state"`
				} `json:"buddies"`
			} `json:"groups"`
		} `json:"buddylist"`
	}
	if err := json.Unmarshal(events, &payload); err != nil {
		return ""
	}
	for _, group := range payload.BuddyList.Groups {
		for _, b := range group.Buddies {
			if b.AimID == buddy {
				return b.State
			}
		}
	}
	return ""
}

// fetch long-polls for the next batch of events.
func (c *webAPITestClient) fetch() (int, []webAPIEvent) {
	status, data := c.session("/aim/fetchEvents", url.Values{
		"seqNum":  {fmt.Sprint(c.seqNum)},
		"timeout": {"500"},
	})
	if status != http.StatusOK {
		return status, nil
	}
	batch := struct {
		Events     []webAPIEvent `json:"events"`
		LastSeqNum uint64        `json:"lastSeqNum"`
	}{}
	assert.NoError(c.t, json.Unmarshal(data, &batch))
	c.seqNum = batch.LastSeqNum
	return status, batch.Events
}

// expect skips events until one of type typ for which match returns true,
// failing the test if none arrives within a few seconds.
func (c *webAPITestClient) expect(typ string, match func(data json.RawMessage) bool) json.RawMessage {
	var skipped []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, events := c.fetch()
		if status != http.StatusOK {
			c.t.Fatalf("%s: fetchEvents status %d waiting for %s event, skipped %q", c.name, status, typ, skipped)
		}
		for _, event := range events {
			if event.Type == typ && match(event.Data) {
				return event.Data
			}
			skipped = append(skipped, event.Type+":"+string(event.Data))
		}
	}
	c.t.Fatalf("%s: timed out waiting for %s event, skipped %q", c.name, typ, skipped)
	return nil
}

// expectEnded waits for the client's session to end. A fetch parked at the
// time gets a sessionEnded event; any later fetch is refused because the
// aimsid no longer resolves.
func (c *webAPITestClient) expectEnded() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, events := c.fetch()
		if status == http.StatusUnauthorized {
			return
		}
		for _, event := range events {
			if event.Type == "sessionEnded" {
				return
			}
		}
	}
	c.t.Fatalf("%s: timed out waiting for the session to end", c.name)
}

// field returns the string at the dotted path in a JSON object.
func field(data json.RawMessage, path string) string {
	var cur any
	if err := json.Unmarshal(data, &cur); err != nil {
		return ""
	}
	for _, key := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[key]
	}
	s, _ := cur.(string)
	return s
}

// hasField returns a matcher for events whose field at path equals want.
func hasField(path string, want string) func(json.RawMessage) bool {
	return func(data json.RawMessage) bool {
		return field(data, path) == want
	}
}

// freeAddr returns a loopback address with a port that is free right now.
func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	addr := ln.Addr().String()
	assert.NoError(t, ln.Close())
	return addr
}

func TestWebAPI_OSCARIntegration(t *testing.T) {
	tocAddr := freeAddr(t)
	webAPIAddr := freeAddr(t)

	t.Setenv("OSCAR_LISTENERS", "LOCAL://127.0.0.1:5190")
	t.Setenv("OSCAR_ADVERTISED_LISTENERS_PLAIN", "LOCAL://127.0.0.1:5190")
	t.Setenv("TOC_LISTENERS", tocAddr)
	t.Setenv("API_LISTENER", "127.0.0.1:0")
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "oscar.sqlite"))
	t.Setenv("DISABLE_AUTH", "true")
	t.Setenv("LOG_LEVEL", "error")
	t.Setenv("WEBAPI_ENABLED", "true")
	t.Setenv("WEBAPI_LISTENERS", webAPIAddr)
	t.Setenv("ICQ_LEGACY_ENABLED", "false")

	deps, err := MakeCommonDeps()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	oscarServer := OSCAR(deps)
	tocServer := TOC(deps, oscarServer)
	webAPIServer := WebAPI(deps, oscarServer)
	go func() {
		_ = tocServer.ListenAndServe()
	}()
	go func() {
		_ = webAPIServer.ListenAndServe()
	}()
	oscarStopped := false
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if !oscarStopped {
			_ = oscarServer.Shutdown(ctx)
		}
		_ = tocServer.Shutdown(ctx)
		_ = webAPIServer.Shutdown(ctx)
	}()

	for _, addr := range []string{tocAddr, webAPIAddr} {
		assert.Eventually(t, func() bool {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		}, 5*time.Second, 10*time.Millisecond)
	}

	baseURL := "http://" + webAPIAddr
	const events = "myInfo,buddylist,presence,im,sentIM,typing"
	const password = "0x2408105c23001130"

	// a web user signs on and adds a TOC user to their buddy list
	alice := startWebAPISession(t, baseURL, "alice", events)
	alice.expect("myInfo", hasField("aimId", "alice"))
	status, _ := alice.session("/buddylist/addBuddy", url.Values{"buddy": {"bob"}, "group": {"Buddies"}})
	assert.Equal(t, http.StatusOK, status)
	alice.expect("buddylist", func(data json.RawMessage) bool {
		return strings.Contains(string(data), `"aimId":"bob"`)
	})

	bob := dialTOC(t, tocAddr, "bob", `toc2_login localhost 9898 bob `+password+` english "TIC:Test" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776`)
	bob.expect(`^SIGN_ON:TOC2\.0$`)
	bob.send("toc2_new_buddies {g:Buddies\nb:alice\n}")
	bob.expect(`^NEW_BUDDY_REPLY2:alice:added$`)
	bob.send("toc_init_done")

	// presence in both directions
	bob.expect(`^UPDATE_BUDDY2:alice:T:`)
	alice.expect("presence", func(data json.RawMessage) bool {
		return field(data, "aimId") == "bob" && field(data, "state") == "online"
	})

	// instant messages in both directions
	status, data := alice.session("/im/sendIM", url.Values{"t": {"bob"}, "message": {"hello bob"}})
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "delivered", field(data, "state"))
	bob.expect(`^IM_IN_ENC2:alice:.*hello bob$`)
	alice.expect("sentIM", hasField("message", "hello bob"))
	bob.send(`toc2_send_im alice "hello alice"`)
	alice.expect("im", func(data json.RawMessage) bool {
		return field(data, "source.aimId") == "bob" && field(data, "message") == "hello alice"
	})

	// typing events relayed from another user
	bob.send("toc2_client_event alice 2")
	alice.expect("typing", func(data json.RawMessage) bool {
		return field(data, "aimId") == "bob" && field(data, "typingStatus") == "typing"
	})

	// a message to an offline user who can't receive offline messages fails
	status, _ = alice.session("/im/sendIM", url.Values{"t": {"nobody"}, "message": {"hello"}})
	assert.Equal(t, 602, status)

	// the buddy list presence query reflects the buddy's state
	status, data = alice.session("/presence/get", url.Values{"bl": {"1"}})
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(data), `"aimId":"bob"`)
	assert.Contains(t, string(data), `"state":"online"`)

	// a full directory lookup isn't charged to the account's rate classes
	dirClass, ok := deps.snacRateLimits.RateClassLookup(wire.Locate, wire.LocateGetDirInfo)
	assert.True(t, ok)
	account := deps.inMemorySessionManager.RetrieveSession(state.NewIdentScreenName("alice"))
	if !assert.NotNil(t, account) {
		t.FailNow()
	}
	before := account.RateLimitStates()[dirClass-1]
	targets := make([]string, 20)
	for i := range targets {
		targets[i] = fmt.Sprintf("user%d", i)
	}
	status, data = alice.session("/memberDir/get", url.Values{"t": {strings.Join(targets, ",")}})
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(data), `"user19"`)
	after := account.RateLimitStates()[dirClass-1]
	assert.Equal(t, before.CurrentLevel, after.CurrentLevel)
	assert.Equal(t, before.LastTime, after.LastTime)

	// ending the web session is seen by buddies
	status, _ = alice.session("/aim/endSession", url.Values{})
	assert.Equal(t, http.StatusOK, status)
	bob.expect(`^UPDATE_BUDDY2:alice:F:`)

	// a web user signing on sees the buddies already online
	alice = startWebAPISession(t, baseURL, "alice", events)
	assert.Equal(t, "online", buddyState(alice.startEvents, "bob"))
	bob.expect(`^UPDATE_BUDDY2:alice:T:`)

	// a single-session login elsewhere ends the web session
	aliceTOC := dialTOC(t, tocAddr, "alice", `toc_signon localhost 9898 alice `+password+` english "TIC:Test"`)
	aliceTOC.expect(`^SIGN_ON:TOC1\.0$`)
	alice.expectEnded()
	status, _ = alice.fetch()
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.NoError(t, aliceTOC.conn.Close())

	assert.NoError(t, bob.conn.Close())

	// shutting down OSCAR ends every connection, web sessions' included
	carol := startWebAPISession(t, baseURL, "carol", events)
	carol.expect("myInfo", hasField("aimId", "carol"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	assert.NoError(t, oscarServer.Shutdown(ctx))
	oscarStopped = true
	assert.Less(t, time.Since(start), 2*time.Second, "an OSCAR connection outlived shutdown")
	carol.expectEnded()
}
