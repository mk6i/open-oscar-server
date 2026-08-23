package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
)

// EventsHandler handles Web AIM API event fetching endpoints.
type EventsHandler struct {
	SessionManager *state.WebAPISessionManager
	Logger         *slog.Logger
}

// FetchEventsData contains the events and metadata.
type FetchEventsData struct {
	Events          []types.Event `json:"events" xml:"events>event"`
	LastSeqNum      uint64        `json:"lastSeqNum" xml:"lastSeqNum"`
	TimeToNextFetch int           `json:"timeToNextFetch" xml:"timeToNextFetch"`
	FetchBaseURL    string        `json:"fetchBaseURL" xml:"fetchBaseURL"`
}

// FetchEvents handles GET /aim/fetchEvents requests with long-polling support.
func (h *EventsHandler) FetchEvents(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := session.AimSID

	// Get sequence number parameter
	var lastSeqNum uint64
	if seqStr := r.URL.Query().Get("seqNum"); seqStr != "" {
		if val, err := strconv.ParseUint(seqStr, 10, 64); err == nil {
			lastSeqNum = val
		}
	}

	// Timeout is in milliseconds (per Web API spec and client behavior).
	timeout := time.Duration(session.FetchTimeout) * time.Millisecond
	if timeoutStr := r.URL.Query().Get("timeout"); timeoutStr != "" {
		if val, err := strconv.Atoi(timeoutStr); err == nil && val > 0 {
			timeout = time.Duration(val) * time.Millisecond
		}
	}

	// Limit maximum timeout to 60 seconds
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	// Create a context with timeout for the fetch operation
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Fetch events from the queue (will block until events available or timeout)
	events, err := session.EventQueue.Fetch(fetchCtx, lastSeqNum, timeout)
	if err != nil {
		if err == context.DeadlineExceeded {
			// Timeout is normal - return empty events array
			events = []types.Event{}
		} else {
			h.Logger.ErrorContext(ctx, "failed to fetch events", "err", err.Error())
			h.sendError(w, r, http.StatusInternalServerError, "failed to fetch events")
			return
		}
	}

	// Determine the last sequence number
	newLastSeqNum := lastSeqNum
	if len(events) > 0 {
		newLastSeqNum = events[len(events)-1].SeqNum
	}

	// Prepare response
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &FetchEventsData{
		Events:          events,
		LastSeqNum:      newLastSeqNum,
		TimeToNextFetch: session.TimeToNextFetch,
		// Include fetchBaseURL with updated sequence number for next request
		FetchBaseURL: fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
			baseURLFromRequest(r), aimsid, newLastSeqNum),
	}

	// AMF3 clients (e.g. Gromit) take the events reshaped: timestamps as floats
	// and the source/dest user objects flattened. That is a payload difference,
	// not just an encoding one, so it stays here rather than in the encoder.
	format := strings.ToLower(r.URL.Query().Get("f"))
	if format == "amf" || format == "amf3" {
		amfResp := map[string]interface{}{
			"response": map[string]interface{}{
				"data": map[string]interface{}{
					"events":          ConvertEventsForAMF3(events),
					"lastSeqNum":      newLastSeqNum,
					"timeToNextFetch": session.TimeToNextFetch,
					"fetchBaseURL": fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
						baseURLFromRequest(r), aimsid, newLastSeqNum),
				},
				"statusCode":       200,
				"statusText":       "OK",
				"statusDetailCode": 0,
			},
		}
		SendResponse(w, r, amfResp, h.Logger)
	} else {
		// Send response in requested format (JSON, JSONP, or XML)
		SendResponse(w, r, resp, h.Logger)
	}

	if len(events) > 0 {
		h.Logger.DebugContext(ctx, "events fetched",
			"aimsid", aimsid,
			"count", len(events),
			"last_seq", newLastSeqNum,
		)
	}
}

// sendError is a convenience method that wraps the common SendError function.
func (h *EventsHandler) sendError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	SendError(w, r, statusCode, message)
}
