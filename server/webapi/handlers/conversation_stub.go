package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/mk6i/open-oscar-server/state"
)

// ConversationStubHandler serves Web AIM conversation/imlog endpoints the
// client calls when syncing chat focus and read state.
type ConversationStubHandler struct {
	SessionManager *state.WebAPISessionManager
	Logger         *slog.Logger
}

func (h *ConversationStubHandler) ok(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// Update records active/focus time for a conversation (fire-and-forget).
func (h *ConversationStubHandler) Update(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r)
}

// Close acknowledges a conversation was closed in the client.
func (h *ConversationStubHandler) Close(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r)
}

// MarkRead acknowledges IM log read state for a buddy.
func (h *ConversationStubHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r)
}

// FetchStoredIMs returns stored IM history for a conversation partner.
func (h *ConversationStubHandler) FetchStoredIMs(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	partner := r.URL.Query().Get("to")
	if partner == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: to")
		return
	}

	q := state.StoredIMQuery{
		PartnerAimID: partner,
		SortOrder:    r.URL.Query().Get("sortOrder"),
		SkipMsgID:    r.URL.Query().Get("skipMsgId"),
		StopMsgID:    r.URL.Query().Get("stopMsgId"),
	}
	if n := r.URL.Query().Get("nToGet"); n != "" {
		if v, err := strconv.Atoi(n); err == nil {
			q.NToGet = v
		}
	}
	if start := r.URL.Query().Get("startTime"); start != "" {
		if v, err := strconv.ParseInt(start, 10, 64); err == nil {
			q.StartTime = v
		}
	}
	if end := r.URL.Query().Get("endTime"); end != "" {
		if v, err := strconv.ParseInt(end, 10, 64); err == nil {
			q.EndTime = v
		}
	}

	msgs := sess.GetStoredIMs(q)

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"msgs": msgs,
	}
	SendResponse(w, r, resp, h.Logger)
}
