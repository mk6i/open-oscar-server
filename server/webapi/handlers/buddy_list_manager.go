package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"slices"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BuddyListManager handles the conversion of OSCAR feedbag data
// to WebAPI buddy list format for web clients.
type BuddyListManager struct {
	feedbagService FeedbagService
	locateService  LocateService
	iconSource     BuddyIconSource
	logger         *slog.Logger
}

// NewBuddyListManager creates a new instance of the buddy list manager.
func NewBuddyListManager(feedbagService FeedbagService, locateService LocateService, iconSource BuddyIconSource, logger *slog.Logger) *BuddyListManager {
	return &BuddyListManager{
		feedbagService: feedbagService,
		locateService:  locateService,
		iconSource:     iconSource,
		logger:         logger,
	}
}

// WebAPIBuddyGroup represents a group in the WebAPI buddy list format.
type WebAPIBuddyGroup struct {
	Name    string            `json:"name"`
	Buddies []WebAPIBuddyInfo `json:"buddies"`
	Recent  bool              `json:"recent,omitempty"`
	Smart   interface{}       `json:"smart,omitempty"` // Can be null or number
}

// WebAPIBuddyInfo represents a buddy in the WebAPI format.
type WebAPIBuddyInfo struct {
	AimID        string   `json:"aimId"`
	DisplayID    string   `json:"displayId"`
	Friendly     string   `json:"friendly,omitempty"` // Viewer's private alias, rendered in preference to DisplayID
	State        string   `json:"state"`              // "online", "offline", "away", "idle"
	StatusMsg    string   `json:"statusMsg,omitempty"`
	AwayMsg      string   `json:"awayMsg,omitempty"`
	OnlineTime   int64    `json:"onlineTime,omitempty"`
	IdleTime     int      `json:"idleTime,omitempty"` // Minutes idle
	UserType     string   `json:"userType"`           // "aim", "icq", "admin"
	Bot          bool     `json:"bot"`
	Service      string   `json:"service,omitempty"` // "AIM", "ICQ" (Web AIM client compares case-sensitively)
	PresenceIcon string   `json:"presenceIcon,omitempty"`
	BuddyIcon    string   `json:"buddyIcon,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	MemberSince  int64    `json:"memberSince,omitempty"`
}

// GetBuddyListForUser retrieves and converts the buddy list for a user.
func (m *BuddyListManager) GetBuddyListForUser(ctx context.Context, sess *state.WebAPISession) ([]WebAPIBuddyGroup, error) {
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve feedbag: %w", err)
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve feedbag: unexpected reply type")
	}
	items := reply.Items

	type buddy struct {
		name  string
		alias string
	}
	type group struct {
		name    string
		buddies map[uint16]buddy
		order   []uint16
	}
	type feedbagBL struct {
		order  []uint16
		groups map[uint16]group
	}
	bl := feedbagBL{groups: make(map[uint16]group)}

	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdGroup {
			continue
		}
		if item.GroupID == 0 {
			val, hasVal := item.Uint16SliceBE(wire.FeedbagAttributesOrder)
			if hasVal {
				bl.order = val
			}
			continue
		}
		name := item.Name
		if name == "" {
			name = "Buddies"
		}
		g := group{
			name:    name,
			buddies: make(map[uint16]buddy),
		}
		val, _ := item.Uint16SliceBE(wire.FeedbagAttributesOrder)
		g.order = val
		bl.groups[item.GroupID] = g
	}

	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdBuddy || item.Name == "" {
			continue
		}
		if _, exists := bl.groups[item.GroupID]; !exists {
			bl.groups[item.GroupID] = group{
				name:    "Buddies",
				buddies: make(map[uint16]buddy),
				order:   nil,
			}
		}
		b := buddy{name: item.Name}
		if val, hasVal := item.String(wire.FeedbagAttributesAlias); hasVal {
			b.alias = val
		}
		g := bl.groups[item.GroupID]
		g.buddies[item.ItemID] = b
		bl.groups[item.GroupID] = g
	}

	groupOrder := bl.order
	if len(groupOrder) == 0 && len(bl.groups) > 0 {
		groupOrder = make([]uint16, 0, len(bl.groups))
		for gid := range bl.groups {
			groupOrder = append(groupOrder, gid)
		}
		slices.Sort(groupOrder)
	}

	var out []WebAPIBuddyGroup
	for _, gid := range groupOrder {
		g, ok := bl.groups[gid]
		if !ok {
			continue
		}
		groupName := g.name
		if groupName == "" {
			groupName = "Buddies"
		}
		wg := WebAPIBuddyGroup{Name: groupName, Buddies: []WebAPIBuddyInfo{}}
		for _, bid := range g.order {
			b, ok := g.buddies[bid]
			if !ok {
				continue
			}
			info := m.getBuddyInfo(ctx, sess.OSCARSession, sess.BaseURL, b.name)
			// The alias belongs in friendly, not displayId: the client renders
			// friendly in preference to displayId but still shows displayId as
			// the buddy's actual screen name.
			info.Friendly = b.alias
			wg.Buddies = append(wg.Buddies, info)
		}
		out = append(out, wg)
	}

	return out, nil
}

// getBuddyInfo retrieves a buddy's current presence by issuing a locate
// UserInfoQuery on behalf of the requesting session's OSCAR instance.
func (m *BuddyListManager) getBuddyInfo(ctx context.Context, instance *state.SessionInstance, baseURL string, buddyName string) WebAPIBuddyInfo {
	// Default to offline. The web client keys users by the normalized aimId and
	// shallow-merges each buddy map onto the shared user object, so a display-form
	// aimId here overwrites the id every other event is keyed by.
	//
	// Feedbag buddy names are stored normalized, so they are not a source of
	// display names. DisplayID is filled in from the locate reply below when the
	// buddy is online, or overridden by the caller's alias when one is set.
	ident := state.NewIdentScreenName(buddyName)
	info := WebAPIBuddyInfo{
		AimID:     ident.String(),
		DisplayID: buddyName,
		State:     "offline",
		UserType:  "aim",
		Bot:       false,
		Service:   "AIM",
	}

	reply, err := m.locateService.UserInfoQuery(ctx, instance, wire.SNACFrame{},
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{
			Type:       uint16(wire.LocateTypeUnavailable), // away message
			ScreenName: ident.String(),
		})
	if err != nil {
		m.logger.WarnContext(ctx, "failed to query buddy info", "screenName", buddyName, "error", err)
		return info
	}

	userInfo, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		// Locate error => buddy is blocked or offline.
		return info
	}

	info.State = "online"
	info.Capabilities = []string{}

	// Publish the icon only now that locate has confirmed the buddy is online and
	// has not blocked the caller. Offline and blocking buddies return above without
	// an icon, so neither their icon nor its activity-revealing hash leaks.
	info.BuddyIcon = m.iconSource.PublishedURL(ctx, baseURL, ident)

	// The locate reply carries the screen name as the buddy formatted it.
	if userInfo.ScreenName != "" {
		info.DisplayID = userInfo.ScreenName
	}

	if tod, ok := userInfo.Uint32BE(wire.OServiceUserInfoSignonTOD); ok {
		info.OnlineTime = int64(tod)
	}

	if userInfo.IsAway() {
		info.State = "away"
		if msg, ok := userInfo.LocateInfo.String(wire.LocateTLVTagsInfoUnavailableData); ok {
			info.AwayMsg = msg
		}
	}

	if idle, ok := userInfo.Uint16BE(wire.OServiceUserInfoIdleTime); ok && idle > 0 {
		info.IdleTime = int(idle)
		if info.State == "online" {
			info.State = "idle"
		}
	}

	return info
}

// RemoveBuddyFromFeedbag removes a buddy from a group (or all groups if allGroups is true) using feedbag delete/update SNACs.
func (m *BuddyListManager) RemoveBuddyFromFeedbag(ctx context.Context, sess *state.WebAPISession, buddyName, groupName string, allGroups bool) (resultCode string, err error) {
	// Buddy items carry the owner's alias for the buddy, and the feedbag service
	// relays a session's own writes only to the owner's other instances, so every
	// method here that rewrites buddy items has to drop the alias cache itself.
	defer sess.InvalidateAliases()

	buddyName = strings.TrimSpace(buddyName)
	if buddyName == "" {
		return "error", fmt.Errorf("empty buddy")
	}

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "remove buddy: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)

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
		delFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		delBody := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := m.feedbagService.DeleteItem(ctx, sess.OSCARSession, delFrame, delBody); err != nil {
			m.logger.ErrorContext(ctx, "remove buddy: Feedbag DeleteItem failed", "err", err.Error())
			return "error", err
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "remove buddy: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// RemoveGroupFromFeedbag deletes a buddy group and updates the root order (TOC DelGroup).
func (m *BuddyListManager) RemoveGroupFromFeedbag(ctx context.Context, sess *state.WebAPISession, requestedGroup string) (resultCode string, err error) {
	defer sess.InvalidateAliases()

	req := strings.TrimSpace(requestedGroup)
	if req == "" {
		return "error", fmt.Errorf("empty group")
	}
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "remove group: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	storedName, found := storedGroupNameForRequest(reply.Items, req)
	if !found {
		return "notFound", nil
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	fl.DeleteGroup(storedName)

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		delFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		delBody := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := m.feedbagService.DeleteItem(ctx, sess.OSCARSession, delFrame, delBody); err != nil {
			m.logger.ErrorContext(ctx, "remove group: Feedbag DeleteItem failed", "err", err.Error())
			return "error", err
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "remove group: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// RenameGroupInFeedbag renames a buddy group, updating the group item in place.
func (m *BuddyListManager) RenameGroupInFeedbag(ctx context.Context, sess *state.WebAPISession, oldGroup, newGroup string) (resultCode string, err error) {
	defer sess.InvalidateAliases()

	oldGroup = strings.TrimSpace(oldGroup)
	newGroup = strings.TrimSpace(newGroup)
	if oldGroup == "" || newGroup == "" {
		return "error", fmt.Errorf("empty group name")
	}
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "rename group: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	storedName, found := storedGroupNameForRequest(reply.Items, oldGroup)
	if !found {
		return "notFound", nil
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
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
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "rename group: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// MoveBuddyInFeedbag moves a buddy to a different group and/or repositions it
// within a group's order.
func (m *BuddyListManager) MoveBuddyInFeedbag(ctx context.Context, sess *state.WebAPISession, buddyName, fromGroup, toGroup, beforeBuddy string) (resultCode string, err error) {
	defer sess.InvalidateAliases()

	buddyName = strings.TrimSpace(buddyName)
	fromGroup = strings.TrimSpace(fromGroup)
	toGroup = strings.TrimSpace(toGroup)
	beforeBuddy = strings.TrimSpace(beforeBuddy)
	if buddyName == "" || fromGroup == "" {
		return "error", fmt.Errorf("empty buddy or group")
	}
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "move buddy: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	storedFrom, found := storedGroupNameForRequest(reply.Items, fromGroup)
	if !found {
		return "notFound", nil
	}
	storedTo := ""
	if toGroup != "" {
		storedTo, found = storedGroupNameForRequest(reply.Items, toGroup)
		if !found {
			return "notFound", nil
		}
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	if err := fl.MoveBuddy(storedFrom, storedTo, buddyName, beforeBuddy); err != nil {
		if errors.Is(err, state.ErrGroupNotFound) || errors.Is(err, state.ErrBuddyNotFound) {
			return "notFound", nil
		}
		m.logger.ErrorContext(ctx, "move buddy: MoveBuddy failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		delFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		delBody := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := m.feedbagService.DeleteItem(ctx, sess.OSCARSession, delFrame, delBody); err != nil {
			m.logger.ErrorContext(ctx, "move buddy: Feedbag DeleteItem failed", "err", err.Error())
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
			insFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
			if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, insFrame, inserts); err != nil {
				m.logger.ErrorContext(ctx, "move buddy: Feedbag InsertItem failed", "err", err.Error())
				return "error", err
			}
		}
		if len(updates) > 0 {
			upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
			if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, updates); err != nil {
				m.logger.ErrorContext(ctx, "move buddy: Feedbag UpdateItem failed", "err", err.Error())
				return "error", err
			}
		}
	}

	return "success", nil
}

// SetBuddyAttributeInFeedbag sets a buddy's friendly (alias) name across all
// groups it belongs to. An empty friendly clears the alias.
func (m *BuddyListManager) SetBuddyAttributeInFeedbag(ctx context.Context, sess *state.WebAPISession, buddyName, friendly string) (resultCode string, err error) {
	defer sess.InvalidateAliases()

	buddyName = strings.TrimSpace(buddyName)
	if buddyName == "" {
		return "error", fmt.Errorf("empty buddy")
	}
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "set buddy attribute: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	found, err := fl.SetBuddyAlias(buddyName, friendly)
	if err != nil {
		m.logger.ErrorContext(ctx, "set buddy attribute: SetBuddyAlias failed", "err", err.Error())
		return "error", err
	}
	if !found {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "set buddy attribute: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// SetGroupAttributeInFeedbag sets a group's collapsed state. An empty group
// targets the unnamed default group.
func (m *BuddyListManager) SetGroupAttributeInFeedbag(ctx context.Context, sess *state.WebAPISession, groupName string, collapsed bool) (resultCode string, err error) {
	defer sess.InvalidateAliases()

	groupName = strings.TrimSpace(groupName)
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := m.feedbagService.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "set group attribute: feedbag query failed", "err", err.Error())
		return "error", err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return "error", fmt.Errorf("unexpected feedbag reply type")
	}

	// An empty group targets the unnamed default group (stored name ""); a named
	// group is resolved through the "Buddies" default-label mapping.
	storedName := ""
	if groupName != "" {
		var found bool
		storedName, found = storedGroupNameForRequest(reply.Items, groupName)
		if !found {
			return "notFound", nil
		}
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	if err := fl.SetGroupCollapsed(storedName, collapsed); err != nil {
		if errors.Is(err, state.ErrGroupNotFound) {
			return "notFound", nil
		}
		m.logger.ErrorContext(ctx, "set group attribute: SetGroupCollapsed failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := m.feedbagService.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "set group attribute: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// FormatBuddyListEvent formats a buddy list for an event.
func (m *BuddyListManager) FormatBuddyListEvent(groups []WebAPIBuddyGroup) map[string]interface{} {
	// Convert groups to a format that AMF3 can properly encode
	// AMF3 has trouble with complex struct slices, so convert to maps
	groupMaps := make([]interface{}, len(groups))
	for i, group := range groups {
		buddyMaps := make([]interface{}, len(group.Buddies))
		for j, buddy := range group.Buddies {
			// Convert each buddy to a map
			buddyMap := map[string]interface{}{
				"aimId":     buddy.AimID,
				"displayId": buddy.DisplayID,
				"state":     buddy.State,
				"userType":  buddy.UserType,
				"bot":       buddy.Bot,
				"service":   buddy.Service,
			}

			// Add optional fields if present
			if buddy.StatusMsg != "" {
				buddyMap["statusMsg"] = buddy.StatusMsg
			}
			if buddy.AwayMsg != "" {
				buddyMap["awayMsg"] = buddy.AwayMsg
			}
			if buddy.OnlineTime > 0 {
				buddyMap["onlineTime"] = float64(buddy.OnlineTime)
			}
			if buddy.IdleTime > 0 {
				buddyMap["idleTime"] = buddy.IdleTime
			}
			if buddy.PresenceIcon != "" {
				buddyMap["presenceIcon"] = buddy.PresenceIcon
			}
			if buddy.BuddyIcon != "" {
				buddyMap["buddyIcon"] = buddy.BuddyIcon
			}
			if len(buddy.Capabilities) > 0 {
				buddyMap["capabilities"] = buddy.Capabilities
			}
			if buddy.MemberSince > 0 {
				buddyMap["memberSince"] = float64(buddy.MemberSince)
			}

			buddyMaps[j] = buddyMap
		}

		// Convert group to a map
		groupMap := map[string]interface{}{
			"name":    group.Name,
			"buddies": buddyMaps,
		}

		// Add optional group fields
		if group.Recent {
			groupMap["recent"] = group.Recent
		}
		if group.Smart != nil {
			groupMap["smart"] = group.Smart
		}

		groupMaps[i] = groupMap
	}

	return map[string]interface{}{
		"groups": groupMaps,
	}
}
