package state

import (
	"sort"
	"strings"
)

// WebAPIStoredIM is one message in a Web AIM session's in-memory IM log.
// The Web AIM client expects fetchStoredIMs entries with sender, message, msgId, and date.
type WebAPIStoredIM struct {
	Sender  string
	Message string
	MsgID   string
	Date    int64 // Unix seconds
}

// AddStoredIM appends a message to the per-partner log for this session.
func (s *WebAPISession) AddStoredIM(partnerAimID, sender, message, msgID string, date int64) {
	if s == nil || partnerAimID == "" || message == "" {
		return
	}
	s.imLogMu.Lock()
	defer s.imLogMu.Unlock()
	if s.imLog == nil {
		s.imLog = make(map[string][]WebAPIStoredIM)
	}
	s.imLog[normalizeWebAPIAimID(partnerAimID)] = append(s.imLog[normalizeWebAPIAimID(partnerAimID)], WebAPIStoredIM{
		Sender:  sender,
		Message: message,
		MsgID:   msgID,
		Date:    date,
	})
}

// StoredIMQuery describes filters for fetchStoredIMs.
type StoredIMQuery struct {
	PartnerAimID string
	StartTime    int64
	EndTime      int64
	NToGet       int
	SortOrder    string
	SkipMsgID    string
	StopMsgID    string
}

// GetStoredIMs returns stored messages for a conversation partner, filtered and sorted
// per the Web AIM client's fetchStoredIMs parameters.
func (s *WebAPISession) GetStoredIMs(q StoredIMQuery) []map[string]interface{} {
	if s == nil || q.PartnerAimID == "" {
		return nil
	}

	s.imLogMu.Lock()
	msgs := append([]WebAPIStoredIM(nil), s.imLog[normalizeWebAPIAimID(q.PartnerAimID)]...)
	s.imLogMu.Unlock()

	if len(msgs) == 0 {
		return []map[string]interface{}{}
	}

	filtered := make([]WebAPIStoredIM, 0, len(msgs))
	for _, msg := range msgs {
		if q.StartTime > 0 && msg.Date < q.StartTime {
			continue
		}
		if q.EndTime > 0 && msg.Date > q.EndTime {
			continue
		}
		filtered = append(filtered, msg)
	}

	descending := strings.EqualFold(q.SortOrder, "descendingDate")
	sort.Slice(filtered, func(i, j int) bool {
		if descending {
			return filtered[i].Date > filtered[j].Date
		}
		return filtered[i].Date < filtered[j].Date
	})

	if q.SkipMsgID != "" {
		for i, msg := range filtered {
			if msg.MsgID == q.SkipMsgID {
				filtered = filtered[i+1:]
				break
			}
		}
	}
	if q.StopMsgID != "" {
		for i, msg := range filtered {
			if msg.MsgID == q.StopMsgID {
				filtered = filtered[:i]
				break
			}
		}
	}

	n := q.NToGet
	if n <= 0 {
		n = 100
	}
	if len(filtered) > n {
		filtered = filtered[:n]
	}

	out := make([]map[string]interface{}, len(filtered))
	for i, msg := range filtered {
		out[i] = map[string]interface{}{
			"sender":  msg.Sender,
			"message": msg.Message,
			"msgId":   msg.MsgID,
			"date":    float64(msg.Date),
		}
	}
	return out
}

// normalizeWebAPIAimID keys the IM log by the same normalization the web client
// applies to aimIds, so a partner stored from a display screen name is still
// found when the client queries by aimId.
func normalizeWebAPIAimID(aimID string) string {
	return NewIdentScreenName(aimID).String()
}
