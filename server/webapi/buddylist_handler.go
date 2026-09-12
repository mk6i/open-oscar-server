package webapi

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BuddyListHandler handles Web AIM API buddy list management endpoints.
type BuddyListHandler struct {
	BuddyListManager *BuddyListManager
	Logger           *slog.Logger
	FeedbagService   FeedbagService
}

// AddBuddy handles GET /buddylist/addBuddy requests.
func (h *BuddyListHandler) AddBuddy(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(param(r, "buddy"))
	groupName := strings.TrimSpace(param(r, "group"))

	preAuthorized := isTrueParam(param(r, "preAuthorized"))
	authorizationMsg := strings.TrimSpace(param(r, "authorizationMsg"))

	if buddyName == "" {
		SendError(w, r, http.StatusBadRequest, "missing buddy parameter")
		return
	}

	if groupName == "" {
		groupName = "Buddies" // Default group
	}

	// Add buddy to feedbag
	resultCode := h.addBuddyToFeedbag(ctx, session, buddyName, groupName, preAuthorized, authorizationMsg)

	// Prepare response
	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy added",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"preAuthorized", preAuthorized,
		"result", resultCode,
	)
}

// AddGroup handles GET /buddylist/addGroup requests.
func (h *BuddyListHandler) AddGroup(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	if groupName == "" {
		SendError(w, r, http.StatusBadRequest, "missing group parameter")
		return
	}

	resultCode := h.addGroupToFeedbag(ctx, session, groupName)

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy list group added",
		"aimsid", aimsid,
		"group", groupName,
		"result", resultCode,
	)
}

func (h *BuddyListHandler) addGroupToFeedbag(ctx context.Context, sess *Session, groupName string) string {
	// A session sees no SNAC for its own feedbag writes, so it drops the alias
	// cache itself. See WebAPISession.InvalidateAliases.
	defer sess.InvalidateAliases()

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

	return resultSuccess
}

// RemoveBuddy handles GET /buddylist/removeBuddy requests.
func (h *BuddyListHandler) RemoveBuddy(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(r.URL.Query().Get("buddy"))
	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	allGroupsParam := r.URL.Query().Get("allGroups")
	allGroups := allGroupsParam == "true" || allGroupsParam == "1"
	if buddyName == "" {
		SendError(w, r, http.StatusBadRequest, "missing buddy parameter")
		return
	}

	resultCode, rmErr := h.BuddyListManager.RemoveBuddyFromFeedbag(ctx, session, buddyName, groupName, allGroups)
	if rmErr != nil {
		h.Logger.ErrorContext(ctx, "remove buddy failed", "err", rmErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy removed",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"result", resultCode,
	)
}

// todo don't remove empty group?
// RemoveGroup handles GET /buddylist/removeGroup requests.
func (h *BuddyListHandler) RemoveGroup(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	if groupName == "" {
		SendError(w, r, http.StatusBadRequest, "missing group parameter")
		return
	}

	resultCode, rmErr := h.BuddyListManager.RemoveGroupFromFeedbag(ctx, session, groupName)
	if rmErr != nil {
		h.Logger.ErrorContext(ctx, "remove group failed", "err", rmErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy list group removed",
		"aimsid", aimsid,
		"group", groupName,
		"result", resultCode,
	)
}

// addBuddyToFeedbag adds a buddy to the user's feedbag.
func (h *BuddyListHandler) addBuddyToFeedbag(ctx context.Context, sess *Session, buddyName, groupName string, preAuthorized bool, authorizationMsg string) string {
	defer sess.InvalidateAliases()

	// Retrieve current feedbag
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := h.FeedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to retrieve feedbag", "err", err.Error())
		return "error"
	}

	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		// todo what
		return "error"
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	target := state.NewIdentScreenName(buddyName)

	fl.AddGroup(groupName)
	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, pending); err != nil {
			h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
			return "error"
		}
	}

	added, err := fl.AddBuddy(groupName, buddyName, "", "")
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to add buddy to feedbag", "err", err.Error())
		return "error"
	}
	if !added {
		return "alreadyExists"
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

		if sess.OSCARSession.UIN() != 0 && target.UIN() != 0 {
			for _, buddies := range buddyItems {
				for i := range buddies {
					if state.NewIdentScreenName(buddies[i].Name) == target {
						buddies[i].Append(wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}))
					}
				}
			}
		}

		for _, buddies := range buddyItems {
			frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
			if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, buddies); err != nil {
				h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
				return "error"
			}
		}

		for _, item := range pending { // todo why not filter buddies out of pending?
			if item.ClassID == wire.FeedbagClassIdGroup {
				frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
				if _, err := h.FeedbagService.UpsertItem(ctx, sess.OSCARSession, frame, []wire.FeedbagItem{item}); err != nil {
					h.Logger.ErrorContext(ctx, "failed to add buddy", "err", err.Error())
					return "error"
				}
			}
		}
	}

	if preAuthorized {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagPreAuthorizeBuddy}
		body := wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{
			ScreenName: buddyName,
			Message:    authorizationMsg,
		}
		if _, err := h.FeedbagService.PreAuthorizeBuddy(ctx, sess.OSCARSession, frame, body); err != nil {
			h.Logger.ErrorContext(ctx, "failed to pre-authorize buddy",
				"buddy", buddyName, "err", err.Error())
		}
	}

	return resultSuccess
}

// RenameGroup handles GET /buddylist/renameGroup requests.
//
// The Web AIM client calls this with oldGroup (current group name) and newGroup
// (the requested new name). This is a stub; it does not yet rename the group in
// the feedbag.
func (h *BuddyListHandler) RenameGroup(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	oldGroup := strings.TrimSpace(r.URL.Query().Get("oldGroup"))
	newGroup := strings.TrimSpace(r.URL.Query().Get("newGroup"))
	if oldGroup == "" || newGroup == "" {
		SendError(w, r, http.StatusBadRequest, "missing oldGroup or newGroup parameter")
		return
	}

	resultCode, rnErr := h.BuddyListManager.RenameGroupInFeedbag(ctx, session, oldGroup, newGroup)
	if rnErr != nil {
		h.Logger.ErrorContext(ctx, "rename group failed", "err", rnErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy list group renamed",
		"aimsid", aimsid,
		"oldGroup", oldGroup,
		"newGroup", newGroup,
		"result", resultCode,
	)
}

// MoveBuddy handles GET /buddylist/moveBuddy requests.
//
// The Web AIM client calls this with buddy (the buddy to move), group (the
// current group), and optionally newGroup (destination group) and beforeBuddy
// (buddy to position it before). This is a stub; it does not yet move the buddy
// in the feedbag.
func (h *BuddyListHandler) MoveBuddy(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(r.URL.Query().Get("buddy"))
	groupName := strings.TrimSpace(r.URL.Query().Get("group"))
	newGroup := strings.TrimSpace(r.URL.Query().Get("newGroup"))
	beforeBuddy := strings.TrimSpace(r.URL.Query().Get("beforeBuddy"))
	if buddyName == "" {
		SendError(w, r, http.StatusBadRequest, "missing buddy parameter")
		return
	}
	if groupName == "" {
		SendError(w, r, http.StatusBadRequest, "missing group parameter")
		return
	}

	resultCode, mvErr := h.BuddyListManager.MoveBuddyInFeedbag(ctx, session, buddyName, groupName, newGroup, beforeBuddy)
	if mvErr != nil {
		h.Logger.ErrorContext(ctx, "move buddy failed", "err", mvErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy moved",
		"aimsid", aimsid,
		"buddy", buddyName,
		"group", groupName,
		"newGroup", newGroup,
		"beforeBuddy", beforeBuddy,
		"result", resultCode,
	)
}

// SetBuddyAttribute handles GET /buddylist/setBuddyAttribute requests.
//
// The Web AIM client calls this with t (the buddy) and friendly (the display
// name / alias). This is a stub; it does not yet persist the attribute to the
// feedbag.
func (h *BuddyListHandler) SetBuddyAttribute(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyName := strings.TrimSpace(r.URL.Query().Get("t"))
	friendly := strings.TrimSpace(r.URL.Query().Get("friendly"))
	if buddyName == "" {
		SendError(w, r, http.StatusBadRequest, "missing t parameter")
		return
	}

	resultCode, saErr := h.BuddyListManager.SetBuddyAttributeInFeedbag(ctx, session, buddyName, friendly)
	if saErr != nil {
		h.Logger.ErrorContext(ctx, "set buddy attribute failed", "err", saErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy attribute set",
		"aimsid", aimsid,
		"buddy", buddyName,
		"friendly", friendly,
		"result", resultCode,
	)
}

// SetGroupAttribute handles GET /buddylist/setGroupAttribute requests.
//
// The Web AIM client calls this with collapsed (the group's collapsed state)
// and, for named groups, group. The unnamed default group omits group. This is
// a stub; it does not yet persist the attribute to the feedbag.
func (h *BuddyListHandler) SetGroupAttribute(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	query := r.URL.Query()
	groupName := strings.TrimSpace(query.Get("group"))
	collapsedParam := strings.TrimSpace(query.Get("collapsed"))
	if collapsedParam == "" {
		SendError(w, r, http.StatusBadRequest, "missing collapsed parameter")
		return
	}
	collapsed := collapsedParam == "true" || collapsedParam == "1"

	resultCode, saErr := h.BuddyListManager.SetGroupAttributeInFeedbag(ctx, session, groupName, collapsed)
	if saErr != nil {
		h.Logger.ErrorContext(ctx, "set group attribute failed", "err", saErr.Error())
	}

	sendMutationResult(w, r, resultCode, h.Logger)

	h.Logger.InfoContext(ctx, "buddy list group attribute set",
		"aimsid", aimsid,
		"group", groupName,
		"collapsed", collapsed,
		"result", resultCode,
	)
}

// resultSuccess is the result code the buddy list methods no longer report; see
// sendMutationResult.
const resultSuccess = "success"

func sendMutationResult(w http.ResponseWriter, r *http.Request, resultCode string, logger *slog.Logger) {
	if resultCode == resultSuccess {
		// Nil data renders as an empty "data":{} — no resultCode, no buddyInfo.
		SendOK(w, r, nil, logger)
		return
	}
	SendOK(w, r, &ResultCodeData{ResultCode: resultCode}, logger)
}

// ResultCodeData is the payload the buddy list editing methods answer with.
//
// The spec shows these methods returning an empty data; the Web AIM client
// reads resultCode from it, so the server sends one.
type ResultCodeData struct {
	ResultCode string `json:"resultCode" xml:"resultCode"`
}
