package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
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
	// Retrieve feedbag items
	items, err := m.feedbagRetriever.RetrieveFeedbag(ctx, screenName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve feedbag: %w", err)
	}

	// Build group map
	groupMap := make(map[uint16]string)
	buddyGroupMap := make(map[uint16][]wire.FeedbagItem)

	for _, item := range items {
		switch item.ClassID {
		case wire.FeedbagClassIdGroup:
			// Store group name
			groupMap[item.ItemID] = item.Name
			buddyGroupMap[item.ItemID] = []wire.FeedbagItem{}
		case wire.FeedbagClassIdBuddy:
			// Add buddy to its group
			if _, exists := buddyGroupMap[item.GroupID]; !exists {
				// Create implicit group if it doesn't exist
				buddyGroupMap[item.GroupID] = []wire.FeedbagItem{}
			}
			buddyGroupMap[item.GroupID] = append(buddyGroupMap[item.GroupID], item)
		}
	}

	// Convert to WebAPI format
	var groups []WebAPIBuddyGroup

	// Add online group (virtual group for online buddies)
	onlineGroup := WebAPIBuddyGroup{
		Name:    "Online",
		Buddies: []WebAPIBuddyInfo{},
	}

	// Process each group
	for groupID, buddyItems := range buddyGroupMap {
		groupName := groupMap[groupID]
		if groupName == "" {
			groupName = "Buddies" // Default group name
		}

		group := WebAPIBuddyGroup{
			Name:    groupName,
			Buddies: []WebAPIBuddyInfo{},
		}

		// Process buddies in this group
		for _, buddyItem := range buddyItems {
			buddyInfo := m.getBuddyInfo(buddyItem.Name)

			// Add to online group if buddy is online
			if buddyInfo.State == "online" || buddyInfo.State == "away" || buddyInfo.State == "idle" {
				onlineGroup.Buddies = append(onlineGroup.Buddies, buddyInfo)
			}

			group.Buddies = append(group.Buddies, buddyInfo)
		}

		// Only add group if it has buddies
		if len(group.Buddies) > 0 {
			groups = append(groups, group)
		}
	}

	// Add online group at the beginning if it has buddies
	if len(onlineGroup.Buddies) > 0 {
		groups = append([]WebAPIBuddyGroup{onlineGroup}, groups...)
	}

	// Always add an "Offline" group at the end for offline buddies
	offlineGroup := WebAPIBuddyGroup{
		Name:    "Offline",
		Buddies: []WebAPIBuddyInfo{},
	}

	// Collect all offline buddies
	for _, group := range groups {
		if group.Name != "Online" {
			for _, buddy := range group.Buddies {
				if buddy.State == "offline" {
					offlineGroup.Buddies = append(offlineGroup.Buddies, buddy)
				}
			}
		}
	}

	if len(offlineGroup.Buddies) > 0 {
		groups = append(groups, offlineGroup)
	}

	return groups, nil
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
	session := m.sessionRetriever.RetrieveSession(buddyScreenName, 0)

	if session != nil {
		// Buddy is online
		info.State = "online"
		info.OnlineTime = session.SignonTime().Unix()

		// Check away status
		if session.AwayMessage() != "" {
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

		// Status messages not currently supported in Session

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
