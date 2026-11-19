package webapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BuddyListManager handles the conversion of OSCAR feedbag data
// to WebAPI buddy list format for web clients.
type BuddyListManager struct {
	iconSource BuddyIconSource
	logger     *slog.Logger
}

// NewBuddyListManager creates a new instance of the buddy list manager.
func NewBuddyListManager(iconSource BuddyIconSource, logger *slog.Logger) *BuddyListManager {
	return &BuddyListManager{
		iconSource: iconSource,
		logger:     logger,
	}
}

// BuddyGroup represents a group in the WebAPI buddy list format.
type BuddyGroup struct {
	Name string `json:"name" xml:"name"`
	// ID is the feedbag group id, read strictly by clients. It follows Name to keep
	// the rendered element order unchanged.
	ID      int         `json:"id" xml:"id"`
	Buddies []BuddyInfo `json:"buddies" xml:"buddies>buddy"`
	Recent  bool        `json:"recent,omitempty" xml:"recent,omitempty"`
	// Smart is null or a number. It is a pointer rather than an interface so
	// encoding/xml can render it: a non-nil interface holding a map cannot be
	// marshalled, while a nil pointer is simply omitted.
	Smart *int `json:"smart,omitempty" xml:"smart,omitempty"`
}

// BuddyInfo represents a buddy in the WebAPI format.
type BuddyInfo struct {
	AimID        string   `json:"aimId" xml:"aimId"`
	DisplayID    string   `json:"displayId" xml:"displayId"`
	Friendly     string   `json:"friendly,omitempty" xml:"friendly,omitempty"` // Viewer's private alias, rendered in preference to DisplayID
	State        string   `json:"state" xml:"state"`                           // "online", "offline", "away", "idle"
	StatusMsg    string   `json:"statusMsg,omitempty" xml:"statusMsg,omitempty"`
	AwayMsg      string   `json:"awayMsg,omitempty" xml:"awayMsg,omitempty"`
	OnlineTime   int64    `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"`
	IdleTime     int      `json:"idleTime,omitempty" xml:"idleTime,omitempty"` // Minutes idle
	UserType     string   `json:"userType" xml:"userType"`                     // "aim", "icq"
	Bot          bool     `json:"bot" xml:"bot"`
	Service      string   `json:"service,omitempty" xml:"service,omitempty"` // Non-native network; omitted for AIM
	PresenceIcon string   `json:"presenceIcon,omitempty" xml:"presenceIcon,omitempty"`
	BuddyIcon    string   `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`
	MoodIcon     string   `json:"moodIcon,omitempty" xml:"moodIcon,omitempty"`
	Capabilities []string `json:"capabilities,omitempty" xml:"capabilities>capability,omitempty"`
	MemberSince  int64    `json:"memberSince,omitempty" xml:"memberSince,omitempty"`
}

// GetBuddyListForUser retrieves and converts the buddy list for a user.
func (m *BuddyListManager) GetBuddyListForUser(ctx context.Context, sess *Session) []BuddyGroup {
	fl := state.NewFeedbagList(sess.Feedbag(), nil)

	out := []BuddyGroup{}
	for _, group := range fl.Groups() {
		groupName := group.Name
		if groupName == "" {
			groupName = "Buddies"
		}
		wg := BuddyGroup{ID: int(group.GroupID), Name: groupName, Buddies: []BuddyInfo{}}
		for _, buddy := range fl.Buddies(group) {
			if buddy.Name == "" {
				continue
			}
			info := m.getBuddyInfo(ctx, sess, buddy.Name)
			// The alias belongs in friendly, not displayId: the client renders
			// friendly in preference to displayId but still shows displayId as
			// the buddy's actual screen name.
			info.Friendly, _ = buddy.String(wire.FeedbagAttributesAlias)
			wg.Buddies = append(wg.Buddies, info)
		}
		out = append(out, wg)
	}

	return out
}

// getBuddyInfo renders a buddy's presence from the session's presence view. A
// buddy the view has never seen renders offline, which at sign-on includes one
// whose arrival has not been drained yet; the presence events correct that.
//
// AwayMsg costs a locate query per unavailable buddy, since an away message is
// absent from presence broadcasts.
func (m *BuddyListManager) getBuddyInfo(ctx context.Context, sess *Session, buddyName string) BuddyInfo {
	// Default to offline. The web client keys users by the normalized aimId and
	// shallow-merges each buddy map onto the shared user object, so a display-form
	// aimId here overwrites the id every other event is keyed by.
	//
	// Feedbag buddy names are stored normalized, so they are not a source of
	// display names. DisplayID is filled in from the presence view below when the
	// buddy is online, or overridden by the caller's alias when one is set.
	ident := state.NewIdentScreenName(buddyName)
	info := BuddyInfo{
		AimID:     ident.String(),
		DisplayID: buddyName,
		State:     "offline",
		UserType:  userTypeFor(ident),
		Service:   serviceFor(ident),
		Bot:       false,
	}

	presence, ok := sess.BuddyPresence(ident)
	if !ok {
		return info
	}

	// A departure keeps the last display name seen, which beats the normalized
	// feedbag spelling.
	if presence.DisplayID != "" {
		info.DisplayID = presence.DisplayID
	}

	info.State = presence.State
	info.StatusMsg = presence.StatusMsg
	info.OnlineTime = presence.OnlineTime
	info.IdleTime = presence.IdleTime

	if !presence.Online() {
		return info
	}

	if hasAwayMsg(presence.State) {
		info.AwayMsg = sess.awayMessage(ctx, ident)
	}

	info.Capabilities = []string{}

	info.BuddyIcon = m.iconSource.URLForHash(sess.BaseURL, ident, presence.IconHash)
	info.MoodIcon = moodIconURL(sess.BaseURL, presence.State, presence.Caps)

	return info
}

// RemoveBuddyFromFeedbag removes a buddy from a group (or all groups if allGroups is true) using feedbag delete/update SNACs.
func (m *BuddyListManager) RemoveBuddyFromFeedbag(ctx context.Context, sess *Session, buddyName, groupName string, allGroups bool) (resultCode string, err error) {
	buddyName = strings.TrimSpace(buddyName)
	if buddyName == "" {
		return "error", fmt.Errorf("empty buddy")
	}

	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	fl := state.NewFeedbagList(items, rand.Intn)

	target := groupName
	if allGroups {
		target = "*"
	}
	if err := fl.DeleteBuddy(target, buddyName); err != nil {
		if errors.Is(err, state.ErrGroupNotFound) {
			return "notFound", nil
		}
		m.logger.ErrorContext(ctx, "remove buddy: DeleteBuddy failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagDeleteItem, pending); err != nil {
			return "error", err
		}
		if !stillListsBuddy(fl.Items(), buddyName) {
			sess.forgetBuddyPresence(state.NewIdentScreenName(buddyName))
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, pending); err != nil {
			return "error", err
		}
	}

	return "success", nil
}

// RemoveGroupFromFeedbag deletes a buddy group and updates the root order (TOC DelGroup).
func (m *BuddyListManager) RemoveGroupFromFeedbag(ctx context.Context, sess *Session, requestedGroup string) (resultCode string, err error) {
	req := strings.TrimSpace(requestedGroup)
	if req == "" {
		return "error", fmt.Errorf("empty group")
	}
	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	storedName, found := storedGroupNameForRequest(items, req)
	if !found {
		return "notFound", nil
	}

	fl := state.NewFeedbagList(items, rand.Intn)
	fl.DeleteGroup(storedName)

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagDeleteItem, pending); err != nil {
			return "error", err
		}

		remaining := fl.Items()
		for _, item := range pending {
			if item.ClassID != wire.FeedbagClassIdBuddy || item.Name == "" {
				continue
			}
			if !stillListsBuddy(remaining, item.Name) {
				sess.forgetBuddyPresence(state.NewIdentScreenName(item.Name))
			}
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, pending); err != nil {
			return "error", err
		}
	}

	return "success", nil
}

// RenameGroupInFeedbag renames a buddy group, updating the group item in place.
func (m *BuddyListManager) RenameGroupInFeedbag(ctx context.Context, sess *Session, oldGroup, newGroup string) (resultCode string, err error) {
	oldGroup = strings.TrimSpace(oldGroup)
	newGroup = strings.TrimSpace(newGroup)
	if oldGroup == "" || newGroup == "" {
		return "error", fmt.Errorf("empty group name")
	}
	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	storedName, found := storedGroupNameForRequest(items, oldGroup)
	if !found {
		return "notFound", nil
	}

	fl := state.NewFeedbagList(items, rand.Intn)
	if err := fl.RenameGroup(storedName, newGroup); err != nil {
		switch {
		case errors.Is(err, state.ErrGroupNotFound):
			return "notFound", nil
		case errors.Is(err, state.ErrGroupExists):
			return "alreadyExists", nil
		default:
			m.logger.ErrorContext(ctx, "rename group: RenameGroup failed", "err", err.Error())
			return "error", err
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, pending); err != nil {
			return "error", err
		}
	}

	return "success", nil
}

// MoveBuddyInFeedbag moves a buddy to a different group and/or repositions it
// within a group's order.
func (m *BuddyListManager) MoveBuddyInFeedbag(ctx context.Context, sess *Session, buddyName, fromGroup, toGroup, beforeBuddy string) (resultCode string, err error) {
	buddyName = strings.TrimSpace(buddyName)
	fromGroup = strings.TrimSpace(fromGroup)
	toGroup = strings.TrimSpace(toGroup)
	beforeBuddy = strings.TrimSpace(beforeBuddy)
	if buddyName == "" || fromGroup == "" {
		return "error", fmt.Errorf("empty buddy or group")
	}
	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	storedFrom, found := storedGroupNameForRequest(items, fromGroup)
	if !found {
		return "notFound", nil
	}
	storedTo := ""
	if toGroup != "" {
		storedTo, found = storedGroupNameForRequest(items, toGroup)
		if !found {
			return "notFound", nil
		}
	}

	fl := state.NewFeedbagList(items, rand.Intn)
	if err := fl.MoveBuddy(storedFrom, storedTo, buddyName, beforeBuddy); err != nil {
		if errors.Is(err, state.ErrGroupNotFound) || errors.Is(err, state.ErrBuddyNotFound) {
			return "notFound", nil
		}
		m.logger.ErrorContext(ctx, "move buddy: MoveBuddy failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagDeleteItem, pending); err != nil {
			return "error", err
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		var inserts, updates []wire.FeedbagItem
		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdBuddy {
				inserts = append(inserts, item)
			} else {
				updates = append(updates, item)
			}
		}
		if len(inserts) > 0 {
			if _, err := sess.changeFeedbag(ctx, wire.FeedbagInsertItem, inserts); err != nil {
				return "error", err
			}
		}
		if len(updates) > 0 {
			if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, updates); err != nil {
				return "error", err
			}
		}
	}

	return "success", nil
}

// SetBuddyAttributeInFeedbag sets a buddy's friendly (alias) name across all
// groups it belongs to. An empty friendly clears the alias.
func (m *BuddyListManager) SetBuddyAttributeInFeedbag(ctx context.Context, sess *Session, buddyName, friendly string) (resultCode string, err error) {
	buddyName = strings.TrimSpace(buddyName)
	if buddyName == "" {
		return "error", fmt.Errorf("empty buddy")
	}
	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	fl := state.NewFeedbagList(items, rand.Intn)
	found, err := fl.SetBuddyAlias(buddyName, friendly)
	if err != nil {
		m.logger.ErrorContext(ctx, "set buddy attribute: SetBuddyAlias failed", "err", err.Error())
		return "error", err
	}
	if !found {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, pending); err != nil {
			return "error", err
		}
	}

	return "success", nil
}

// SetGroupAttributeInFeedbag sets a group's collapsed state. An empty group
// targets the unnamed default group.
func (m *BuddyListManager) SetGroupAttributeInFeedbag(ctx context.Context, sess *Session, groupName string, collapsed bool) (resultCode string, err error) {
	groupName = strings.TrimSpace(groupName)
	items, err := sess.lockFeedbag(ctx)
	if err != nil {
		return "error", err
	}
	defer sess.unlockFeedbag()

	// An empty group targets the unnamed default group (stored name ""); a named
	// group is resolved through the "Buddies" default-label mapping.
	storedName := ""
	if groupName != "" {
		var found bool
		storedName, found = storedGroupNameForRequest(items, groupName)
		if !found {
			return "notFound", nil
		}
	}

	fl := state.NewFeedbagList(items, rand.Intn)
	if err := fl.SetGroupCollapsed(storedName, collapsed); err != nil {
		if errors.Is(err, state.ErrGroupNotFound) {
			return "notFound", nil
		}
		m.logger.ErrorContext(ctx, "set group attribute: SetGroupCollapsed failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if _, err := sess.changeFeedbag(ctx, wire.FeedbagUpdateItem, pending); err != nil {
			return "error", err
		}
	}

	return "success", nil
}

// stillListsBuddy reports whether buddyName appears among items. Callers deleting
// a buddy from one group use it to tell a partial removal from a full one: a buddy
// listed in several groups is still watched after leaving one of them, so their
// cached presence is still maintained.
func stillListsBuddy(items []wire.FeedbagItem, buddyName string) bool {
	want := state.NewIdentScreenName(buddyName)
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdBuddy {
			continue
		}
		if state.NewIdentScreenName(item.Name) == want {
			return true
		}
	}
	return false
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
