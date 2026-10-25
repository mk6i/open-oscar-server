package toc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
)

// ensure correct behavior during global context cancellation (server shutdown)
func TestServer_handleTOCRequest_serverShutdown(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer wg.Done()
		sv := Server{
			bosProxy: testOSCARProxy(t),
			logger:   slog.Default(),
		}

		serverReader, _ := io.Pipe()

		fc := wire.NewFlapClient(0, serverReader, nil)
		closeConn := func() {
			_ = serverReader.Close()
		}
		me, _ := newTestTOCConn(newTestSession("me"))
		err := sv.handleTOCRequest(ctx, closeConn, me, fc)
		assert.True(t, errors.Is(err, errTOCProcessing) || errors.Is(err, errServerWrite))
	}()

	// cancel context, simulating server shutdown
	cancel()

	// wait for handleTOCRequest to return
	wg.Wait()
}

// ensure correct behavior when client TCP connection disconnects
func TestServer_handleTOCRequest_clientReadDisconnect(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	serverReader, _ := io.Pipe()

	go func() {
		defer wg.Done()
		closeConn := func() {
			_ = serverReader.Close()
		}
		me, _ := newTestTOCConn(newTestSession("me"))
		fc := wire.NewFlapClient(0, serverReader, nil)

		sv := Server{
			bosProxy: testOSCARProxy(t),
			logger:   slog.Default(),
		}
		err := sv.handleTOCRequest(context.Background(), closeConn, me, fc)
		assert.ErrorIs(t, err, errClientReq)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	}()

	// simulate a client TCP disconnect
	_ = serverReader.Close()

	// wait for handleTOCRequest to return
	wg.Wait()
}

// ensure correct behavior when session gets closed by another login
func TestServer_handleTOCRequest_sessClose(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	me, bos := newTestTOCConn(newTestSession("me"))

	go func() {
		defer wg.Done()

		serverReader, _ := io.Pipe()
		fc := wire.NewFlapClient(0, serverReader, nil)

		closeConn := func() {
			_ = serverReader.Close()
		}

		sv := Server{
			bosProxy: testOSCARProxy(t),
			logger:   slog.Default(),
		}
		err := sv.handleTOCRequest(context.Background(), closeConn, me, fc)
		assert.ErrorIs(t, err, errTOCProcessing)
		assert.ErrorIs(t, err, errDisconnect)
	}()

	// close the BOS connection, simulating another client login kicking this
	// session
	bos.Close()

	// wait for handleTOCRequest to return
	wg.Wait()
}

// ensure correct behavior when writing server response fails
func TestServer_handleTOCRequest_replyFailure(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	go func() {
		defer wg.Done()
		closeConn := func() {
			_ = serverReader.Close()
		}
		me, _ := newTestTOCConn(newTestSession("me"))
		fc := wire.NewFlapClient(0, serverReader, serverWriter)

		sv := Server{
			bosProxy: testOSCARProxy(t),
			logger:   slog.Default(),
		}
		err := sv.handleTOCRequest(context.Background(), closeConn, me, fc)
		assert.ErrorIs(t, err, errServerWrite)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	}()

	// simulate a failed TCP write
	_ = serverWriter.Close()

	// set up a TOC client
	fc := wire.NewFlapClient(0, clientReader, clientWriter)

	// send a TOC command
	err := fc.SendDataFrame([]byte(`toc_get_status`))
	assert.NoError(t, err)

	// wait for handleTOCRequest to return
	wg.Wait()
}

// ensure correct behavior when writing server response fails
func TestServer_handleTOCRequest_happyPath(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	go func() {
		defer wg.Done()
		closeConn := func() {
			_ = serverReader.Close()
		}
		fc := wire.NewFlapClient(0, serverReader, serverWriter)
		sv := Server{
			bosProxy: testOSCARProxy(t),
			logger:   slog.Default(),
		}
		me, _ := newTestTOCConn(newTestSession("me"))
		err := sv.handleTOCRequest(context.Background(), closeConn, me, fc)
		assert.ErrorIs(t, err, errClientReq)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	}()

	// set up a TOC client
	fc := wire.NewFlapClient(0, clientReader, clientWriter)

	// send a malformed TOC command to the server
	err := fc.SendDataFrame([]byte(`toc_get_status`))
	assert.NoError(t, err)

	// wait for the TOC response from the server
	frame, err := fc.ReceiveFLAP()
	assert.NoError(t, err)

	// expecting an error from TOC because the command is malformed. this
	// demonstrates that a command was processed by the TOC handler.
	assert.Contains(t, string(frame.Payload), "internal server error")

	// cleanly disconnect
	_ = serverReader.Close()

	// wait for handleTOCRequest to return
	wg.Wait()
}
