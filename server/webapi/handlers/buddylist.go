package handlers

import (
	"context"
	"log/slog"
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
	SessionManager WebAPISessionManager
	FeedbagManager FeedbagManager
	Logger         *slog.Logger
}

// FeedbagManager provides methods to manage buddy lists.
type FeedbagManager interface {
	RetrieveFeedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error)
	InsertItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error
	UpdateItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error
	DeleteItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error
}

// AddBuddy handles GET /buddylist/addBuddy requests.
func (h *BuddyListHandler) AddBuddy(w http.ResponseWriter, r *http.Request) {
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

	// Touch the session
	h.SessionManager.TouchSession(r.Context(), aimsid)

	// Get buddy and group parameters
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
	resultCode, buddyInfo := h.addBuddyToFeedbag(ctx, session.ScreenName.IdentScreenName(), buddyName, groupName)

	// Prepare response
	responseData := map[string]interface{}{
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

	if resultCode == "success" && session.EventQueue != nil {
		// Push buddy list update event to the session's event queue
		event := types.BuddyListEvent{
			Action: "add",
			Buddy:  buddyInfo,
			Group:  groupName,
		}
		session.EventQueue.Push(types.EventTypeBuddyList, event)
	}

	h.Logger.InfoContext(ctx, "buddy added",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"result", resultCode,
	)
}

// addBuddyToFeedbag adds a buddy to the user's feedbag.
func (h *BuddyListHandler) addBuddyToFeedbag(ctx context.Context, screenName state.IdentScreenName, buddyName, groupName string) (string, *BuddyPresenceInfo) {
	// Retrieve current feedbag
	items, err := h.FeedbagManager.RetrieveFeedbag(ctx, screenName)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		return "error", nil
	}

	// Check if buddy already exists
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy && item.Name == buddyName {
			// Buddy already exists
			return "alreadyExists", nil
		}
	}

	// Find or create the group
	var groupID uint16
	groupFound := false
	maxGroupID := uint16(0)

	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdGroup {
			if item.ItemID > maxGroupID {
				maxGroupID = item.ItemID
			}

			// Check group name
			if item.Name == groupName {
				groupID = item.ItemID
				groupFound = true
			}
		}
	}

	// If group doesn't exist, create it
	if !groupFound {
		groupID = maxGroupID + 1
		groupItem := wire.FeedbagItem{
			ItemID:    groupID,
			ClassID:   wire.FeedbagClassIdGroup,
			Name:      groupName,
			GroupID:   0,
			TLVLBlock: wire.TLVLBlock{},
		}

		if err := h.FeedbagManager.InsertItem(ctx, screenName, groupItem); err != nil {
			h.Logger.ErrorContext(ctx, "failed to create group", "err", err.Error())
			return "error", nil
		}
	}

	// Find next available item ID for buddy
	maxBuddyID := uint16(0)
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy && item.ItemID > maxBuddyID {
			maxBuddyID = item.ItemID
		}
	}

	// Create buddy item
	buddyItem := wire.FeedbagItem{
		ItemID:    maxBuddyID + 1,
		ClassID:   wire.FeedbagClassIdBuddy,
		Name:      buddyName,
		GroupID:   groupID,
		TLVLBlock: wire.TLVLBlock{},
	}

	// Insert buddy into feedbag
	if err := h.FeedbagManager.InsertItem(ctx, screenName, buddyItem); err != nil {
		h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
		return "error", nil
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
func (h *BuddyListHandler) AddTempBuddy(w http.ResponseWriter, r *http.Request) {
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

	// Touch the session
	h.SessionManager.TouchSession(r.Context(), aimsid)

	// Get buddy names from parameters
	// The WebAPI accepts multiple buddy names via &t= parameters
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
	responseData := map[string]interface{}{
		"resultCode": "success",
		"buddyNames": buddyNames,
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = responseData
	SendResponse(w, r, resp, h.Logger)

	// Push temp buddy event to the session's event queue
	if session.EventQueue != nil {
		for _, buddyName := range buddyNames {
			buddyName = strings.TrimSpace(buddyName)
			if buddyName != "" {
				// Create minimal buddy info for temp buddy
				buddyInfo := &BuddyPresenceInfo{
					AimID:    buddyName,
					State:    "offline", // Default state
					UserType: "aim",
				}

				event := types.BuddyListEvent{
					Action: "addTemp",
					Buddy:  buddyInfo,
				}
				session.EventQueue.Push(types.EventTypeBuddyList, event)
			}
		}
	}

	h.Logger.InfoContext(ctx, "temporary buddies added",
		"aimsid", aimsid,
		"buddies", buddyNames,
		"count", len(buddyNames),
	)
}

// sendError is a convenience method that wraps the common SendError function.
func (h *BuddyListHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	SendError(w, statusCode, message)
}
