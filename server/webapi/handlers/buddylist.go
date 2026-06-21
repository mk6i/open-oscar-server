package handlers

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// WebAPISessionManager provides methods to manage WebAPI sessions.
type WebAPISessionManager interface {
	GetSession(ctx context.Context, aimsid string) (*state.WebAPISession, error)
	TouchSession(ctx context.Context, aimsid string) error
}

// BuddyListHandler handles Web AIM API buddy list management endpoints.
type BuddyListHandler struct {
	SessionManager   WebAPISessionManager
	BuddyListManager *BuddyListManager
	Logger           *slog.Logger
	FeedbagService   FeedbagService
	mux              *http.ServeMux
}

func NewBuddyListHandler(sessionManager WebAPISessionManager, blm *BuddyListManager, logger *slog.Logger, feedbagService FeedbagService) *BuddyListHandler {
	h := &BuddyListHandler{
		SessionManager:   sessionManager,
		BuddyListManager: blm,
		Logger:           logger,
		FeedbagService:   feedbagService,
	}
	m := http.NewServeMux()
	m.Handle("GET /buddylist/addBuddy", h.SessionMiddleware(h.AddBuddy))
	m.Handle("GET /buddylist/addGroup", h.SessionMiddleware(h.AddGroup))
	m.Handle("GET /buddylist/removeBuddy", h.SessionMiddleware(h.RemoveBuddy))
	m.Handle("GET /buddylist/removeGroup", h.SessionMiddleware(h.RemoveGroup))
	h.mux = m
	return h
}

func (h *BuddyListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *BuddyListHandler) SessionMiddleware(next func(http.ResponseWriter, *http.Request, *state.WebAPISession)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aimsid := r.URL.Query().Get("aimsid")
		if aimsid == "" {
			h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
			return
		}
		session, err := h.SessionManager.GetSession(r.Context(), aimsid)
		if err != nil {
			switch err {
			case state.ErrNoWebAPISession:
				h.sendError(w, http.StatusNotFound, "session not found")
			case state.ErrWebAPISessionExpired:
				h.sendError(w, http.StatusGone, "session expired")
			default:
				h.sendError(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}
		_ = h.SessionManager.TouchSession(r.Context(), aimsid)
		next(w, r, session)
	})
}

type FeedbagService interface {
	DeleteItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (*wire.SNACMessage, error)
	Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error)
	QueryIfModified(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x05_FeedbagQueryIfModified) (wire.SNACMessage, error)
	RespondAuthorizeToHost(ctx context.Context, instance state.IdentScreenName, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost) error
	RightsQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	StartCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x11_FeedbagStartCluster)
	EndCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) error
	UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, items []wire.FeedbagItem) (*wire.SNACMessage, error)
	Use(ctx context.Context, instance *state.SessionInstance) error
}

// AddBuddy handles GET /buddylist/addBuddy requests.
func (h *BuddyListHandler) AddBuddy(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(r.URL.Query().Get("buddy"))
	groupName := strings.TrimSpace(r.URL.Query().Get("group"))

	if buddyName == "" {
		h.sendError(w, http.StatusBadRequest, "missing buddy parameter")
		return
	}

	if groupName == "" {
		groupName = "Buddies" // Default group
	}

	// Add buddy to feedbag
	resultCode, buddyInfo := h.addBuddyToFeedbag(ctx, session, buddyName, groupName)

	// Prepare response
	responseData := map[string]any{
		"resultCode": resultCode,
	}
	if resultCode == "success" {
		responseData["buddyInfo"] = buddyInfo
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = responseData
	SendResponse(w, r, resp, h.Logger)

	if resultCode == "success" {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to get buddy list for event", "err", err.Error())
		} else {
			blPayload := map[string]any{"groups": groups}
			session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
		}
	}

	h.Logger.InfoContext(ctx, "buddy added",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"result", resultCode,
	)
}

// AddGroup handles GET /buddylist/addGroup requests.
func (h *BuddyListHandler) AddGroup(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	if groupName == "" {
		h.sendError(w, http.StatusBadRequest, "missing group parameter")
		return
	}

	resultCode := h.addGroupToFeedbag(ctx, session, groupName)

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]any{
		"resultCode": resultCode,
	}
	SendResponse(w, r, resp, h.Logger)

	if resultCode == "success" {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to get buddy list for event", "err", err.Error())
		} else {
			blPayload := map[string]any{"groups": groups}
			session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
		}
	}

	h.Logger.InfoContext(ctx, "buddy list group added",
		"aimsid", aimsid,
		"group", groupName,
		"result", resultCode,
	)
}

func (h *BuddyListHandler) addGroupToFeedbag(ctx context.Context, sess *state.WebAPISession, groupName string) string {
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := h.FeedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		return "error"
	}

	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error"
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	fl.AddGroup(groupName)

	pending := fl.PendingUpdates()
	if len(pending) == 0 {
		return "alreadyExists"
	}

	insertFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
	if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, insertFrame, pending); err != nil {
		h.Logger.ErrorContext(ctx, "failed to add group", "err", err.Error())
		return "error"
	}

	return "success"
}

// feedbagGroupMatchesRequested returns true if a feedbag group row matches the
// group the Web client asked for. OSCAR often stores the default group with an
// empty name; GetBuddyListForUser labels that as "Buddies", so addBuddy must
// treat "" and "Buddies" as the same bucket when the client sends group=Buddies.
func feedbagGroupMatchesRequested(storedName, requested string) bool {
	req := strings.TrimSpace(requested)
	st := strings.TrimSpace(storedName)
	if strings.EqualFold(st, req) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(req), "Buddies") && st == "" {
		return true
	}
	return false
}

// findFeedbagGroupID returns the ItemID of a group matching requested, or false if none.
func findFeedbagGroupID(items []wire.FeedbagItem, requested string) (uint16, bool) {
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdGroup {
			continue
		}
		if feedbagGroupMatchesRequested(item.Name, requested) {
			return item.ItemID, true
		}
	}
	return 0, false
}

// storedGroupNameForRequest returns the feedbag group row Name for a Web client group label.
// Rows with GroupID 0 are the root order record, not a named buddy group.
func storedGroupNameForRequest(items []wire.FeedbagItem, requested string) (string, bool) {
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdGroup {
			continue
		}
		if item.GroupID == 0 {
			continue
		}
		if feedbagGroupMatchesRequested(item.Name, requested) {
			return item.Name, true
		}
	}
	return "", false
}

// RemoveBuddy handles GET /buddylist/removeBuddy requests.
func (h *BuddyListHandler) RemoveBuddy(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(r.URL.Query().Get("buddy"))
	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	allGroupsParam := r.URL.Query().Get("allGroups")
	allGroups := allGroupsParam == "true" || allGroupsParam == "1"
	if buddyName == "" {
		h.sendError(w, http.StatusBadRequest, "missing buddy parameter")
		return
	}

	resultCode, rmErr := h.BuddyListManager.RemoveBuddyFromFeedbag(ctx, session, buddyName, groupName, allGroups)
	if rmErr != nil {
		h.Logger.ErrorContext(ctx, "remove buddy failed", "err", rmErr.Error())
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]any{
		"resultCode": resultCode,
	}
	SendResponse(w, r, resp, h.Logger)

	if resultCode == "success" {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to get buddy list for event", "err", err.Error())
		} else {
			blPayload := map[string]any{"groups": groups}
			session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
		}
	}

	h.Logger.InfoContext(ctx, "buddy removed",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"result", resultCode,
	)
}

// todo don't remove empty group?
// RemoveGroup handles GET /buddylist/removeGroup requests.
func (h *BuddyListHandler) RemoveGroup(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	if groupName == "" {
		h.sendError(w, http.StatusBadRequest, "missing group parameter")
		return
	}

	resultCode, rmErr := h.BuddyListManager.RemoveGroupFromFeedbag(ctx, session, groupName)
	if rmErr != nil {
		h.Logger.ErrorContext(ctx, "remove group failed", "err", rmErr.Error())
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]any{
		"resultCode": resultCode,
	}
	SendResponse(w, r, resp, h.Logger)

	if resultCode == "success" {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to get buddy list for event", "err", err.Error())
		} else {
			blPayload := map[string]any{"groups": groups}
			session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
		}
	}

	h.Logger.InfoContext(ctx, "buddy list group removed",
		"aimsid", aimsid,
		"group", groupName,
		"result", resultCode,
	)
}

// addBuddyToFeedbag adds a buddy to the user's feedbag.
func (h *BuddyListHandler) addBuddyToFeedbag(ctx context.Context, sess *state.WebAPISession, buddyName, groupName string) (string, *BuddyPresenceInfo) {
	// Retrieve current feedbag
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := h.FeedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		return "error", nil
	}

	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		// todo what
		return "error", nil
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)

	fl.AddGroup(groupName)
	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, pending); err != nil {
			h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
			return "error", nil
		}
	}

	added, err := fl.AddBuddy(groupName, buddyName, "", "")
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to add buddy to feedbag", "err", err.Error())
		return "error", nil
	}
	if !added {
		return "alreadyExists", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {

		buddyItems := make(map[uint16][]wire.FeedbagItem)
		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdBuddy {
				if _, ok := buddyItems[item.GroupID]; !ok {
					buddyItems[item.GroupID] = nil
				}
				buddyItems[item.GroupID] = append(buddyItems[item.GroupID], item)
			}
		}

		for _, buddies := range buddyItems {
			frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
			if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, buddies); err != nil {
				h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
				return "error", nil
			}
		}

		for _, item := range pending { // todo why not filter buddies out of pending?
			if item.ClassID == wire.FeedbagClassIdGroup {
				frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
				if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, []wire.FeedbagItem{item}); err != nil {
					h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
					return "error", nil
				}
			}
		}
	}

	// Get current presence for the buddy
	buddyInfo := &BuddyPresenceInfo{
		AimID:    buddyName,
		State:    "offline", // Default to offline
		UserType: "aim",
	}

	// TODO: Check actual presence status and update buddyInfo accordingly

	return "success", buddyInfo
}

// AddTempBuddy handles GET /aim/addTempBuddy requests.
// This adds temporary buddies to the session without persisting them to the feedbag.
// The temporary buddies are only visible for the duration of the session.
func (h *BuddyListHandler) AddTempBuddy(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyNames := r.URL.Query()["t"]
	if len(buddyNames) == 0 {
		h.sendError(w, http.StatusBadRequest, "missing buddy names (t parameter)")
		return
	}

	// Store temporary buddies in the session
	// Note: These are not persisted to the feedbag database
	if session.TempBuddies == nil {
		session.TempBuddies = make(map[string]bool)
	}

	for _, buddyName := range buddyNames {
		buddyName = strings.TrimSpace(buddyName)
		if buddyName != "" {
			session.TempBuddies[buddyName] = true
		}
	}

	// Prepare response
	responseData := map[string]any{
		"resultCode": "success",
		"buddyNames": buddyNames,
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = responseData
	SendResponse(w, r, resp, h.Logger)

	// Do not push buddylist events for temp buddies. The Web AIM client handles
	// addTempBuddy via the API response; a buddylist event without "groups" causes
	// the client to clear the entire contact list (zC always calls clear() first).

	h.Logger.InfoContext(ctx, "temporary buddies added",
		"aimsid", aimsid,
		"buddies", buddyNames,
		"count", len(buddyNames),
	)
}

// RemoveTempBuddy handles GET /aim/removeTempBuddy requests.
// This removes temporary session buddies added via addTempBuddy.
func (h *BuddyListHandler) RemoveTempBuddy(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyNames := r.URL.Query()["t"]
	if len(buddyNames) == 0 {
		h.sendError(w, http.StatusBadRequest, "missing buddy names (t parameter)")
		return
	}

	removed := make([]string, 0, len(buddyNames))
	for _, buddyName := range buddyNames {
		buddyName = strings.TrimSpace(buddyName)
		if buddyName == "" {
			continue
		}
		if session.TempBuddies != nil {
			delete(session.TempBuddies, buddyName)
		}
		removed = append(removed, buddyName)
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]any{
		"resultCode": "success",
		"buddyNames": removed,
	}
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "temporary buddies removed",
		"aimsid", aimsid,
		"buddies", removed,
		"count", len(removed),
	)
}

// sendError is a convenience method that wraps the common SendError function.
func (h *BuddyListHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	SendError(w, statusCode, message)
}
