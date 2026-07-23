package types

import "time"

// ConversationEventData builds a conversation fetchEvents payload.
func ConversationEventData(operation string, conversations []map[string]interface{}) map[string]interface{} {
	if conversations == nil {
		conversations = []map[string]interface{}{}
	}
	return map[string]interface{}{
		"operation":     operation,
		"conversations": conversations,
	}
}

// ConversationGroupEntry builds one group-chat conversation object for the Web
// AIM client's conversation "list". The presence of the imserv field is what
// makes the client render the entry under "Group Chats" (its aa() predicate);
// displayID gives the room its name without a getSettings round-trip.
func ConversationGroupEntry(imserv, displayID string, memberCount int) map[string]interface{} {
	entry := map[string]interface{}{
		"imserv":       imserv,
		"aimId":        imserv,
		"active":       0,
		"memberCounts": memberCount,
	}
	if displayID != "" {
		entry["displayId"] = displayID
	}
	return entry
}

// ConversationEntry builds one conversation object for the Web AIM client.
//
// An empty displayID is omitted rather than sent blank: the client falls back to
// the name it already has for aimID, whereas any value present here replaces it.
func ConversationEntry(aimID, displayID, message, msgID, sender string, sent bool, unread int) map[string]interface{} {
	entry := map[string]interface{}{
		"aimId":       aimID,
		"active":      0,
		"unreadCount": unread,
	}
	if displayID != "" {
		entry["displayId"] = displayID
	}
	if message != "" {
		entry["lastIM"] = map[string]interface{}{
			"message":   message,
			"msgId":     msgID,
			"sender":    sender,
			"sent":      sent,
			"timestamp": float64(time.Now().Unix()),
		}
	}
	return entry
}
