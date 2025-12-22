package handlers

import (
	"context"
	"encoding/xml"
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

// FetchEventsResponse represents the response for fetchEvents endpoint.
type FetchEventsResponse struct {
	Response struct {
		StatusCode int             `json:"statusCode"`
		StatusText string          `json:"statusText"`
		Data       FetchEventsData `json:"data"`
	} `json:"response"`
}

// FetchEventsData contains the events and metadata.
type FetchEventsData struct {
	Events          []types.Event `json:"events"`
	LastSeqNum      uint64        `json:"lastSeqNum"`
	TimeToNextFetch int           `json:"timeToNextFetch"`
	FetchBaseURL    string        `json:"fetchBaseURL"`
}

// FetchEventsXMLResponse represents the XML response for fetchEvents endpoint.
type FetchEventsXMLResponse struct {
	XMLName    xml.Name `xml:"response"`
	StatusCode int      `xml:"statusCode"`
	StatusText string   `xml:"statusText"`
	Data       struct {
		Events          []types.Event `xml:"events>event"`
		LastSeqNum      uint64        `xml:"lastSeqNum"`
		TimeToNextFetch int           `xml:"timeToNextFetch"`
		FetchBaseURL    string        `xml:"fetchBaseURL"`
	} `xml:"data"`
}

// FetchEvents handles GET /aim/fetchEvents requests with long-polling support.
func (h *EventsHandler) FetchEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		if err == state.ErrNoWebAPISession {
			h.sendError(w, http.StatusNotFound, "session not found")
		} else if err == state.ErrWebAPISessionExpired {
			h.sendError(w, http.StatusGone, "session expired")
		} else {
			h.sendError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Touch the session to update last accessed time
	h.SessionManager.TouchSession(r.Context(), aimsid)

	// Get sequence number parameter
	var lastSeqNum uint64
	if seqStr := r.URL.Query().Get("seqNum"); seqStr != "" {
		if val, err := strconv.ParseUint(seqStr, 10, 64); err == nil {
			lastSeqNum = val
		}
	}

	// Get timeout parameter (in seconds, convert to milliseconds)
	timeout := time.Duration(session.FetchTimeout) * time.Millisecond
	if timeoutStr := r.URL.Query().Get("timeout"); timeoutStr != "" {
		if val, err := strconv.Atoi(timeoutStr); err == nil && val > 0 {
			timeout = time.Duration(val) * time.Second
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
			h.sendError(w, http.StatusInternalServerError, "failed to fetch events")
			return
		}
	}

	// Determine the last sequence number
	var newLastSeqNum uint64 = lastSeqNum
	if len(events) > 0 {
		newLastSeqNum = events[len(events)-1].SeqNum
	}

	// Prepare response
	resp := FetchEventsResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data.Events = events
	resp.Response.Data.LastSeqNum = newLastSeqNum
	resp.Response.Data.TimeToNextFetch = session.TimeToNextFetch
	// Include fetchBaseURL with updated sequence number for next request
	resp.Response.Data.FetchBaseURL = fmt.Sprintf("http://%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
		r.Host, aimsid, newLastSeqNum)

	// Check response format
	format := strings.ToLower(r.URL.Query().Get("f"))

	if format == "xml" {
		// Send XML response
		xmlResp := FetchEventsXMLResponse{}
		xmlResp.StatusCode = 200
		xmlResp.StatusText = "OK"
		xmlResp.Data.Events = events
		xmlResp.Data.LastSeqNum = newLastSeqNum
		xmlResp.Data.TimeToNextFetch = session.TimeToNextFetch
		xmlResp.Data.FetchBaseURL = fmt.Sprintf("http://%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
			r.Host, aimsid, newLastSeqNum)

		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`)
		if err := xml.NewEncoder(w).Encode(xmlResp); err != nil {
			h.Logger.Error("failed to encode XML response", "error", err)
		}
	} else if format == "amf" || format == "amf3" {
		// For AMF3, build the response with fields in the correct order
		// The working implementation has: response { data {...}, statusCode, statusText, statusDetailCode }
		// Convert events to ensure timestamps are float64 for AMF3
		convertedEvents := ConvertEventsForAMF3(events)

		amfResp := map[string]interface{}{
			"response": map[string]interface{}{
				// Data comes FIRST (Gromit processes this large object)
				"data": map[string]interface{}{
					"events":          convertedEvents,
					"lastSeqNum":      newLastSeqNum,
					"timeToNextFetch": session.TimeToNextFetch,
					"fetchBaseURL": fmt.Sprintf("http://%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
						r.Host, aimsid, newLastSeqNum),
				},
				// Status fields come AFTER data
				"statusCode":       200,
				"statusText":       "OK",
				"statusDetailCode": 0,
			},
		}

		// Use SendResponse which will detect AMF format and encode properly
		SendResponse(w, r, amfResp, h.Logger)
	} else {
		// Send JSON/JSONP response with standard structure
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
func (h *EventsHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	SendError(w, statusCode, message)
}
