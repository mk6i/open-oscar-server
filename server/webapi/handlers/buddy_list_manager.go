package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"slices"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// BuddyListManager handles the conversion of OSCAR feedbag data
// to WebAPI buddy list format for web clients.
type BuddyListManager struct {
	feedbagRetriever FeedbagRetriever
	sessionRetriever SessionRetriever
	logger           *slog.Logger
}

// NewBuddyListManager creates a new instance of the buddy list manager.
func NewBuddyListManager(feedbagRetriever FeedbagRetriever, sessionRetriever SessionRetriever, logger *slog.Logger) *BuddyListManager {
	return &BuddyListManager{
		feedbagRetriever: feedbagRetriever,
		sessionRetriever: sessionRetriever,
		logger:           logger,
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
	State        string   `json:"state"` // "online", "offline", "away", "idle"
	StatusMsg    string   `json:"statusMsg,omitempty"`
	AwayMsg      string   `json:"awayMsg,omitempty"`
	OnlineTime   int64    `json:"onlineTime,omitempty"`
	IdleTime     int      `json:"idleTime,omitempty"` // Minutes idle
	UserType     string   `json:"userType"`           // "aim", "icq", "admin"
	Bot          bool     `json:"bot"`
	Service      string   `json:"service,omitempty"` // "aim", "icq"
	PresenceIcon string   `json:"presenceIcon,omitempty"`
	BuddyIcon    string   `json:"buddyIcon,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	MemberSince  int64    `json:"memberSince,omitempty"`
}

// GetBuddyListForUser retrieves and converts the buddy list for a user.
func (m *BuddyListManager) GetBuddyListForUser(ctx context.Context, screenName state.IdentScreenName) ([]WebAPIBuddyGroup, error) {
	items, err := m.feedbagRetriever.RetrieveFeedbag(ctx, screenName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve feedbag: %w", err)
	}

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
		wg := WebAPIBuddyGroup{Name: groupName}
		for _, bid := range g.order {
			b, ok := g.buddies[bid]
			if !ok {
				continue
			}
			info := m.getBuddyInfo(b.name)
			if b.alias != "" {
				info.DisplayID = b.alias
			}
			wg.Buddies = append(wg.Buddies, info)
		}
		out = append(out, wg)
	}

	return out, nil
}

// getBuddyInfo retrieves the current presence information for a buddy.
func (m *BuddyListManager) getBuddyInfo(buddyName string) WebAPIBuddyInfo {
	// Default to offline
	info := WebAPIBuddyInfo{
		AimID:     buddyName,
		DisplayID: buddyName,
		State:     "offline",
		UserType:  "aim",
		Bot:       false,
		Service:   "aim",
	}

	// Check if buddy is online
	buddyScreenName := state.NewIdentScreenName(buddyName)
	session := m.sessionRetriever.RetrieveSession(buddyScreenName)

	if session != nil {
		// Buddy is online
		info.State = "online"
		info.OnlineTime = session.SignonTime().Unix()

		// Check away status
		if session.Away() {
			info.State = "away"
			info.AwayMsg = session.AwayMessage()
		}

		// Check idle status
		if session.Idle() {
			idleDuration := time.Since(session.IdleTime())
			info.IdleTime = int(idleDuration.Minutes())
			if info.State == "online" {
				info.State = "idle"
			}
		}

		// Status messages not currently supported in SessionInstance

		// Set capabilities
		// Capabilities parsing not implemented
		info.Capabilities = []string{}
	}

	return info
}

// GetPresenceForBuddy retrieves presence information for a specific buddy.
func (m *BuddyListManager) GetPresenceForBuddy(screenName string) WebAPIBuddyInfo {
	return m.getBuddyInfo(screenName)
}

// GetOnlineBuddies returns a list of all online buddies for a user.
func (m *BuddyListManager) GetOnlineBuddies(ctx context.Context, userScreenName state.IdentScreenName) ([]WebAPIBuddyInfo, error) {
	// Get user's buddy list
	items, err := m.feedbagRetriever.RetrieveFeedbag(ctx, userScreenName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve feedbag: %w", err)
	}

	var onlineBuddies []WebAPIBuddyInfo

	// Check each buddy's presence
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy {
			buddyInfo := m.getBuddyInfo(item.Name)
			if buddyInfo.State != "offline" {
				onlineBuddies = append(onlineBuddies, buddyInfo)
			}
		}
	}

	return onlineBuddies, nil
}

// RemoveBuddyFromFeedbag removes a buddy from one group using feedbag delete/update SNACs.
func (m *BuddyListManager) RemoveBuddyFromFeedbag(ctx context.Context, sess *state.WebAPISession, buddyName, requestedGroup string, fb FeedbagService) (resultCode string, err error) {
	buddyName = strings.TrimSpace(buddyName)
	if buddyName == "" {
		return "error", fmt.Errorf("empty buddy")
	}
	req := strings.TrimSpace(requestedGroup)
	if req == "" {
		req = "Buddies"
	}
	if sess.OSCARSession == nil {
		return "error", fmt.Errorf("no OSCAR session")
	}

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := fb.Query(ctx, sess.OSCARSession, frame)
	if err != nil {
		m.logger.ErrorContext(ctx, "remove buddy: feedbag query failed", "err", err.Error())
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
	if err := fl.DeleteBuddy(storedName, buddyName); err != nil {
		m.logger.ErrorContext(ctx, "remove buddy: DeleteBuddy failed", "err", err.Error())
		return "error", err
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		delFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		delBody := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: pending}
		if _, err := fb.DeleteItem(ctx, sess.OSCARSession, delFrame, delBody); err != nil {
			m.logger.ErrorContext(ctx, "remove buddy: Feedbag DeleteItem failed", "err", err.Error())
			return "error", err
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := fb.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "remove buddy: Feedbag UpsertItem failed", "err", err.Error())
			return "error", err
		}
	}

	return "success", nil
}

// RemoveGroupFromFeedbag deletes a buddy group and updates the root order (TOC DelGroup).
func (m *BuddyListManager) RemoveGroupFromFeedbag(ctx context.Context, sess *state.WebAPISession, requestedGroup string, fb FeedbagService) (resultCode string, err error) {
	req := strings.TrimSpace(requestedGroup)
	if req == "" {
		return "error", fmt.Errorf("empty group")
	}
	if sess.OSCARSession == nil {
		return "error", fmt.Errorf("no OSCAR session")
	}

	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := fb.Query(ctx, sess.OSCARSession, frame)
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
		if _, err := fb.DeleteItem(ctx, sess.OSCARSession, delFrame, delBody); err != nil {
			m.logger.ErrorContext(ctx, "remove group: Feedbag DeleteItem failed", "err", err.Error())
			return "error", err
		}
	} else {
		return "notFound", nil
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		upFrame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := fb.UpsertItem(ctx, sess.OSCARSession, upFrame, pending); err != nil {
			m.logger.ErrorContext(ctx, "remove group: Feedbag UpsertItem failed", "err", err.Error())
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
