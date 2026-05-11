package webapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// FeedbagAdapter wraps SQLiteUserStore to implement FeedbagRetriever and FeedbagManager interfaces
type FeedbagAdapter struct {
	Store *state.SQLiteUserStore
}

// RetrieveFeedbag implements FeedbagRetriever interface
func (f *FeedbagAdapter) RetrieveFeedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error) {
	return f.Store.Feedbag(ctx, screenName)
}

// RelationshipsByUser implements FeedbagRetriever interface. It returns the
// contacts on the user's buddy list, including legacy client-side buddy list
// entries that are not represented as feedbag items.
func (f *FeedbagAdapter) RelationshipsByUser(ctx context.Context, screenName state.IdentScreenName) ([]state.IdentScreenName, error) {
	return f.Store.ClientSideBuddies(ctx, screenName)
}

// InsertItem implements FeedbagManager interface
func (f *FeedbagAdapter) InsertItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	// Use FeedbagUpsert to insert a new item
	return f.Store.FeedbagUpsert(ctx, screenName, []wire.FeedbagItem{item})
}

// UpdateItem implements FeedbagManager interface
func (f *FeedbagAdapter) UpdateItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	// Use FeedbagUpsert to update an existing item
	return f.Store.FeedbagUpsert(ctx, screenName, []wire.FeedbagItem{item})
}

// DeleteItem implements FeedbagManager interface
func (f *FeedbagAdapter) DeleteItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	// Use FeedbagDelete to remove an item
	return f.Store.FeedbagDelete(ctx, screenName, []wire.FeedbagItem{item})
}

// AddBuddy adds a buddy to the user's client-side buddy list.
func (f *FeedbagAdapter) AddBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error {
	return f.Store.AddBuddy(ctx, me, them)
}

// RemoveBuddy removes a buddy from the user's client-side buddy list.
func (f *FeedbagAdapter) RemoveBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error {
	return f.Store.RemoveBuddy(ctx, me, them)
}

// DenyBuddy adds a buddy to the user's deny list.
func (f *FeedbagAdapter) DenyBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error {
	return f.Store.DenyBuddy(ctx, me, them)
}

// Message Conversion Functions

// WebAPIToICBM converts a Web API message to OSCAR ICBM format
func WebAPIToICBM(sender state.IdentScreenName, recipient string, message string, autoResponse bool) (wire.SNAC_0x04_0x06_ICBMChannelMsgToHost, error) {
	// Generate message cookie
	var cookie [8]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{}, err
	}
	cookieUint64 := binary.BigEndian.Uint64(cookie[:])

	// Create ICBM fragment list for the message
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{}, err
	}

	// Marshal the fragments
	buf := &bytes.Buffer{}
	for _, frag := range frags {
		if err := wire.MarshalBE(frag, buf); err != nil {
			return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{}, err
		}
	}

	// Build ICBM message
	icbmMsg := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     cookieUint64,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: recipient,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVAOLIMData, buf.Bytes()),
			},
		},
	}

	// Add auto-response flag if applicable
	if autoResponse {
		icbmMsg.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}

	return icbmMsg, nil
}

// ICBMToWebAPIEvent converts an incoming ICBM message to a WebAPI event
func ICBMToWebAPIEvent(icbm wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) (types.Event, error) {
	// Extract message text
	var messageText string
	var autoResponse bool

	// Check for AOL IM data
	if msgData, hasMsg := icbm.Bytes(wire.ICBMTLVAOLIMData); hasMsg {
		msgText, err := wire.UnmarshalICBMMessageText(msgData)
		if err == nil {
			messageText = msgText
		}
	}

	// Check for auto-response flag
	if _, hasAutoResp := icbm.Bytes(wire.ICBMTLVAutoResponse); hasAutoResp {
		autoResponse = true
	}

	// Extract sender screen name from TLVUserInfo
	senderScreenName := ""
	if icbm.TLVUserInfo.ScreenName != "" {
		senderScreenName = icbm.TLVUserInfo.ScreenName
	}

	// Create WebAPI event
	event := types.Event{
		Type:      types.EventTypeIM,
		Timestamp: time.Now().Unix(),
		Data: types.IMEvent{
			From:      senderScreenName,
			Message:   messageText,
			Timestamp: float64(time.Now().Unix()),
			AutoResp:  autoResponse,
		},
	}

	return event, nil
}

// TypingNotificationToWebAPIEvent converts an OSCAR typing notification to a WebAPI event
func TypingNotificationToWebAPIEvent(notification wire.SNAC_0x04_0x14_ICBMClientEvent) types.Event {
	typing := false
	switch notification.Event {
	case 0x0002: // Typing started
		typing = true
	case 0x0001: // Typing stopped
		typing = false
	}

	return types.Event{
		Type:      types.EventTypeTyping,
		Timestamp: time.Now().Unix(),
		Data: types.TypingEvent{
			From:   notification.ScreenName,
			Typing: typing,
		},
	}
}

// PresenceUpdateToWebAPIEvent converts OSCAR buddy arrival/departure to WebAPI event
func PresenceUpdateToWebAPIEvent(screenName string, online bool, awayMsg string, statusBitmask uint32) types.Event {
	stateStr := "offline"
	if online {
		stateStr = "online"
		if statusBitmask&wire.OServiceUserStatusAway != 0 {
			stateStr = "away"
		} else if statusBitmask&wire.OServiceUserStatusDND != 0 {
			stateStr = "dnd"
		} else if statusBitmask&wire.OServiceUserStatusInvisible != 0 {
			stateStr = "invisible"
		}
	}

	return types.Event{
		Type:      types.EventTypePresence,
		Timestamp: time.Now().Unix(),
		Data: types.PresenceEvent{
			AimID:   screenName,
			State:   stateStr,
			AwayMsg: awayMsg,
		},
	}
}
