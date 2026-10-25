package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

// tocTestClient is a TOC client connected to the TOC server under test.
type tocTestClient struct {
	t     *testing.T
	name  string
	conn  net.Conn
	flapc *wire.FlapClient
	lines chan string
}

// dialTOC connects a TOC client to addr and sends the signon command.
func dialTOC(t *testing.T, addr string, screenName string, signonCmd string) *tocTestClient {
	conn, err := net.Dial("tcp", addr)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	_, err = conn.Write([]byte("FLAPON\r\n\r\n"))
	assert.NoError(t, err)

	flapc := wire.NewFlapClient(0, conn, conn)
	_, err = flapc.ReceiveSignonFrame()
	assert.NoError(t, err)
	assert.NoError(t, flapc.SendSignonFrame([]wire.TLV{wire.NewTLVBE(0x01, screenName)}))

	c := &tocTestClient{
		t:     t,
		name:  screenName,
		conn:  conn,
		flapc: flapc,
		lines: make(chan string, 100),
	}
	go func() {
		defer close(c.lines)
		for {
			frame, err := flapc.ReceiveFLAP()
			if err != nil {
				return
			}
			if frame.FrameType == wire.FLAPFrameData {
				c.lines <- string(frame.Payload)
			}
		}
	}()
	c.send(signonCmd)
	return c
}

func (c *tocTestClient) send(cmd string) {
	assert.NoError(c.t, c.flapc.SendDataFrame(append([]byte(cmd), 0)))
}

// expect skips lines until one matches pattern, failing the test if none does
// within a few seconds. It returns the match and its submatches.
func (c *tocTestClient) expect(pattern string) []string {
	rx := regexp.MustCompile(pattern)
	var skipped []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-c.lines:
			if !ok {
				c.t.Fatalf("%s: connection closed waiting for /%s/, skipped %q", c.name, pattern, skipped)
			}
			if m := rx.FindStringSubmatch(line); m != nil {
				return m
			}
			skipped = append(skipped, line)
		case <-timeout:
			c.t.Fatalf("%s: timed out waiting for /%s/, skipped %q", c.name, pattern, skipped)
		}
	}
}

// TestTOC_OSCARIntegration drives TOC clients through the TOC server against a
// real OSCAR server that TOC reaches over in-memory OSCAR connections.
func TestTOC_OSCARIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	tocAddr := ln.Addr().String()
	assert.NoError(t, ln.Close())

	t.Setenv("OSCAR_LISTENERS", "LOCAL://127.0.0.1:5190")
	t.Setenv("OSCAR_ADVERTISED_LISTENERS_PLAIN", "LOCAL://127.0.0.1:5190")
	t.Setenv("TOC_LISTENERS", tocAddr)
	t.Setenv("API_LISTENER", "127.0.0.1:0")
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "oscar.sqlite"))
	t.Setenv("DISABLE_AUTH", "true")
	t.Setenv("LOG_LEVEL", "error")
	t.Setenv("WEBAPI_ENABLED", "false")
	t.Setenv("ICQ_LEGACY_ENABLED", "false")

	deps, err := MakeCommonDeps()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	oscarServer := OSCAR(deps)
	tocServer := TOC(deps, oscarServer)
	go func() {
		_ = tocServer.ListenAndServe()
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = oscarServer.Shutdown(ctx)
		_ = tocServer.Shutdown(ctx)
	}()

	assert.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", tocAddr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)

	const password = "0x2408105c23001130"

	alice := dialTOC(t, tocAddr, "alice", `toc2_login localhost 9898 alice `+password+` english "TIC:Test" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776`)
	alice.expect(`^SIGN_ON:TOC2\.0$`)
	alice.expect(`^NICK:alice$`)
	alice.expect(`^CONFIG2:done:\n$`)
	alice.send("toc2_new_buddies {g:Buddies\nb:bob\n}")
	alice.expect(`^NEW_BUDDY_REPLY2:bob:added$`)
	alice.send("toc_init_done")

	bob := dialTOC(t, tocAddr, "bob", `toc_signon localhost 9898 bob `+password+` english "TIC:Test"`)
	bob.expect(`^SIGN_ON:TOC1\.0$`)
	bob.expect(`^CONFIG:$`)
	bob.expect(`^NICK:bob$`)
	bob.send("toc_add_buddy alice")
	bob.send("toc_init_done")

	// presence in both directions
	alice.expect(`^UPDATE_BUDDY2:bob:T:0:\d+:0:.{3}:$`)
	bob.expect(`^UPDATE_BUDDY:alice:T:0:\d+:0:.{3}$`)

	// instant messages in both directions
	bob.send(`toc_send_im alice "hello alice"`)
	alice.expect(`^IM_IN_ENC2:bob:F:F:T:...:F:L:en:hello alice$`)
	alice.send(`toc2_send_im bob "hello bob"`)
	bob.expect(`^IM_IN:alice:F:hello bob$`)

	// a reply that only makes sense next to its request
	bob.send("toc_get_status nobody")
	bob.expect(`^ERROR:901:nobody$`)

	// the room is announced before its first member list
	alice.send(`toc_chat_join 4 "Integration Room"`)
	alice.expect(`^CHAT_JOIN:0:Integration Room$`)
	alice.expect(`^CHAT_UPDATE_BUDDY:0:T:alice$`)
	alice.send(`toc_chat_send 0 "hello room"`)
	alice.expect(`^CHAT_IN_ENC:0:alice:F:A:en:hello room$`)

	// invitations, accepting them, and leaving rooms
	alice.send(`toc_chat_invite 0 "join us" bob`)
	invite := bob.expect(`^CHAT_INVITE:Integration Room:(\d+):alice:join us$`)
	bob.send("toc_chat_accept " + invite[1])
	bob.expect(`^CHAT_JOIN:` + invite[1] + `:Integration Room$`)
	alice.expect(`^CHAT_UPDATE_BUDDY:0:T:bob$`)
	bob.send("toc_chat_leave " + invite[1])
	bob.expect(`^CHAT_LEFT:` + invite[1] + `$`)
	alice.expect(`^CHAT_UPDATE_BUDDY:0:F:bob$`)

	// a large buddy list addition is stored in full
	var newBuddies strings.Builder
	for i := range 60 {
		fmt.Fprintf(&newBuddies, "g:Group %02d\nb:buddy%02d\n", i, i)
	}
	alice.send("toc2_new_buddies {" + newBuddies.String() + "}")
	for i := range 60 {
		alice.expect(fmt.Sprintf(`^NEW_BUDDY_REPLY2:buddy%02d:added$`, i))
	}
	// alice's commands are handled in order, so her buddy list is stored once
	// this reply arrives
	alice.send("toc_get_status alice")
	alice.expect(`^UPDATE_BUDDY2:alice:T:`)
	alice2 := dialTOC(t, tocAddr, "alice", `toc2_login localhost 9898 alice `+password+` english "TIC:Test" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776`)
	config := alice2.expect(`^CONFIG2:(?s:.*)$`)[0]
	for i := range 60 {
		assert.Contains(t, config, fmt.Sprintf("g:Group %02d\nb:buddy%02d\n", i, i))
	}
	assert.NotContains(t, config, "b:\n")
	assert.NoError(t, alice2.conn.Close())

	// a TOC1 user's deny list hides them from the denied user
	carol := dialTOC(t, tocAddr, "carol", `toc_signon localhost 9898 carol `+password+` english "TIC:Test"`)
	carol.expect(`^NICK:carol$`)
	carol.send("toc_add_deny dave")
	carol.send("toc_init_done")
	// carol's commands are handled in order, so she's signed on once this
	// reply arrives
	carol.send("toc_get_status carol")
	carol.expect(`^UPDATE_BUDDY:carol:T:`)
	dave := dialTOC(t, tocAddr, "dave", `toc_signon localhost 9898 dave `+password+` english "TIC:Test"`)
	dave.expect(`^NICK:dave$`)
	dave.send("toc_init_done")
	dave.send("toc_get_status carol")
	dave.expect(`^ERROR:901:carol$`)
	bob.send("toc_get_status carol")
	bob.expect(`^UPDATE_BUDDY:carol:T:`)
	assert.NoError(t, carol.conn.Close())
	assert.NoError(t, dave.conn.Close())

	// signing off is seen by buddies
	assert.NoError(t, bob.conn.Close())
	alice.expect(`^UPDATE_BUDDY2:bob:F:0:0:0:   :$`)
	assert.NoError(t, alice.conn.Close())
}
