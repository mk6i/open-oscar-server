package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// NewFeedbagService creates a new instance of FeedbagService.
func NewFeedbagService(
	logger *slog.Logger,
	messageRelayer MessageRelayer,
	feedbagManager FeedbagManager,
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
) FeedbagService {
	return FeedbagService{
		bartItemManager:  bartItemManager,
		buddyBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		feedbagManager:   feedbagManager,
		logger:           logger,
		messageRelayer:   messageRelayer,
	}
}

// FeedbagService provides functionality for the Feedbag food group, which
// handles buddy list management.
type FeedbagService struct {
	bartItemManager  BARTItemManager
	buddyBroadcaster buddyBroadcaster
	feedbagManager   FeedbagManager
	logger           *slog.Logger
	messageRelayer   MessageRelayer
}

// RightsQuery returns SNAC wire.FeedbagRightsReply, which contains Feedbag
// food group settings for the current user. The values within the SNAC are not
// well understood but seem to make the AIM client happy.
func (s FeedbagService) RightsQuery(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	// maxItemsByClass defines per-type item limits. Types not listed here are
	// 0 by default. The slice size is equal to the maximum "enum" value+1.
	maxItemsByClass := make([]uint16, 21)
	maxItemsByClass[wire.FeedbagClassIdBuddy] = 61
	maxItemsByClass[wire.FeedbagClassIdGroup] = 61
	maxItemsByClass[wire.FeedbagClassIDPermit] = 100
	maxItemsByClass[wire.FeedbagClassIDDeny] = 100
	maxItemsByClass[wire.FeedbagClassIdPdinfo] = 1
	maxItemsByClass[wire.FeedbagClassIdBuddyPrefs] = 1
	maxItemsByClass[wire.FeedbagClassIdNonbuddy] = 50
	maxItemsByClass[wire.FeedbagClassIdClientPrefs] = 3
	maxItemsByClass[wire.FeedbagClassIdWatchList] = 128
	maxItemsByClass[wire.FeedbagClassIdIgnoreList] = 255
	maxItemsByClass[wire.FeedbagClassIdDateTime] = 20
	maxItemsByClass[wire.FeedbagClassIdExternalUser] = 200
	maxItemsByClass[wire.FeedbagClassIdRootCreator] = 1
	maxItemsByClass[wire.FeedbagClassIdImportTimestamp] = 1
	maxItemsByClass[wire.FeedbagClassIdBart] = 200

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRightsReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x13_0x03_FeedbagRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagRightsMaxItemAttrs, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxItemsByClass, maxItemsByClass),
					wire.NewTLVBE(wire.FeedbagRightsMaxClientItems, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxItemNameLen, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxRecentBuddies, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionBuddies, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionHalfLife, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionMaxScore, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxBuddiesPerGroup, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxMegaBots, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxSmartGroups, uint16(100)),
				},
			},
		},
	}
}

// Query fetches the user's feedbag (aka buddy list). It returns
// wire.FeedbagReply, which contains feedbag entries.
func (s FeedbagService) Query(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame) (wire.SNACMessage, error) {
	fb, err := s.feedbagManager.Feedbag(ctx, sess.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}

	lm := time.UnixMilli(0)

	if len(fb) > 0 {
		lm, err = s.feedbagManager.FeedbagLastModified(ctx, sess.IdentScreenName())
		if err != nil {
			return wire.SNACMessage{}, err
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x13_0x06_FeedbagReply{
			Version:    0,
			Items:      fb,
			LastUpdate: uint32(lm.Unix()),
		},
	}, nil
}

// QueryIfModified fetches the user's feedbag (aka buddy list). It returns
// wire.FeedbagReplyNotModified if the feedbag was last modified before
// inBody.LastUpdate, else return wire.FeedbagReply, which contains feedbag
// entries.
func (s FeedbagService) QueryIfModified(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x05_FeedbagQueryIfModified) (wire.SNACMessage, error) {
	fb, err := s.feedbagManager.Feedbag(ctx, sess.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}

	lm := time.UnixMilli(0)

	if len(fb) > 0 {
		lm, err = s.feedbagManager.FeedbagLastModified(ctx, sess.IdentScreenName())
		if err != nil {
			return wire.SNACMessage{}, err
		}
		if lm.Before(time.Unix(int64(inBody.LastUpdate), 0)) {
			return wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReplyNotModified,
					RequestID: inFrame.RequestID,
				},
				Body: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
					LastUpdate: uint32(lm.Unix()),
					Count:      uint8(len(fb)),
				},
			}, nil
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x13_0x06_FeedbagReply{
			Version:    0,
			Items:      fb,
			LastUpdate: uint32(lm.Unix()),
		},
	}, nil
}

// UpsertItem updates items in the user's feedbag (aka buddy list). Sends user
// buddy arrival notifications for each online & visible buddy added to the
// feedbag. Sends a buddy departure notification to blocked buddies if current
// user is visible. It returns wire.FeedbagStatus, which contains insert
// confirmation.
// UpdateItem updates items in the user's feedbag (aka buddy list). Sends user
// buddy arrival notifications for each online & visible buddy added to the
// feedbag. It returns wire.FeedbagStatus, which contains update confirmation.
func (s FeedbagService) UpsertItem(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, items []wire.FeedbagItem) (wire.SNACMessage, error) {
	for _, item := range items {
		// don't let users block themselves, it causes the AIM client to go
		// into a weird state.
		if item.ClassID == 3 && state.NewIdentScreenName(item.Name) == sess.IdentScreenName() {
			return wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagErr,
					RequestID: inFrame.RequestID,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotSupportedByHost,
				},
			}, nil
		}
	}

	if err := s.feedbagManager.FeedbagUpsert(ctx, sess.IdentScreenName(), items); err != nil {
		return wire.SNACMessage{}, err
	}

	setSessionBuddyPrefs(items, sess)

	var filter []state.IdentScreenName
	var alertAll bool
	for _, item := range items {
		switch item.ClassID {
		case wire.FeedbagClassIdBuddy, wire.FeedbagClassIDPermit, wire.FeedbagClassIDDeny:
			filter = append(filter, state.NewIdentScreenName(item.Name))
		case wire.FeedbagClassIdBart:
			if err := s.setBARTItem(ctx, sess, item); err != nil {
				return wire.SNACMessage{}, err
			}
		case wire.FeedbagClassIdPdinfo:
			alertAll = true
		}
	}

	if alertAll || len(filter) > 0 {
		if err := s.buddyBroadcaster.BroadcastVisibility(ctx, sess, filter, true); err != nil {
			return wire.SNACMessage{}, err
		}
	}

	snacPayloadOut := wire.SNAC_0x13_0x0E_FeedbagStatus{}
	for range items {
		snacPayloadOut.Results = append(snacPayloadOut.Results, 0x0000)
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagStatus,
			RequestID: inFrame.RequestID,
		},
		Body: snacPayloadOut,
	}, nil
}

// setBARTItem informs clients about buddy icon update. If the BART
// store doesn't have the icon, then tell the client to upload the buddy icon.
// If the icon already exists, tell the user's buddies about the icon change.
func (s FeedbagService) setBARTItem(ctx context.Context, sess *state.Session, item wire.FeedbagItem) error {
	b, hasBuf := item.Bytes(wire.FeedbagAttributesBartInfo)
	if !hasBuf {
		return errors.New("unable to extract icon payload")
	}

	itemType, err := strconv.ParseUint(item.Name, 0, 16)
	if err != nil {
		return fmt.Errorf("invalid BART item type %q: %w", item.Name, err)
	}

	bartID := wire.BARTID{
		Type: uint16(itemType),
	}
	if err := wire.UnmarshalBE(&bartID.BARTInfo, bytes.NewBuffer(b)); err != nil {
		return err
	}

	itemExists := false

	if bytes.Equal(bartID.Hash, wire.GetClearIconHash()) {
		s.logger.DebugContext(ctx, "user is clearing icon",
			"hash", fmt.Sprintf("%x", bartID.Hash))
		itemExists = true
	} else {
		existingItem, err := s.bartItemManager.BARTItem(ctx, bartID.Hash)
		if err != nil {
			return err
		}
		itemExists = len(existingItem) > 0
	}

	if itemExists {
		if bartID.Type == wire.BARTTypesBuddyIconSmall || bartID.Type == wire.BARTTypesBuddyIcon {
			sess.SetBuddyIcon(bartID)
			// tell buddies about the icon update
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, sess.IdentScreenName(), sess.TLVUserInfo()); err != nil {
				return err
			}
		}
		s.logger.DebugContext(ctx, "icon already exists in BART store, don't upload the icon file",
			"hash", fmt.Sprintf("%x", bartID.Hash))
	} else {
		// icon doesn't exist, tell the client to upload buddy icon
		bartID.Flags |= wire.BARTFlagsUnknown
		if bartID.Type == wire.BARTTypesBuddyIconSmall || bartID.Type == wire.BARTTypesBuddyIcon {
			sess.SetBuddyIcon(bartID)
		}
		s.logger.DebugContext(ctx, "icon doesn't exist in BART store, client must upload the icon file",
			"hash", fmt.Sprintf("%x", bartID.Hash))
	}

	s.messageRelayer.RelayToScreenName(ctx, sess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceBartReply,
		},
		Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
			BARTID: bartID,
		},
	})

	if bartID.Type == wire.BARTTypesBuddyIconSmall || bartID.Type == wire.BARTTypesBuddyIcon {
		s.messageRelayer.RelayToScreenName(ctx, sess.IdentScreenName(), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceUserInfoUpdate,
			},
			Body: newOServiceUserInfoUpdate(sess),
		})
	}

	return nil
}

// DeleteItem removes items from feedbag (aka buddy list). Sends user buddy
// arrival notifications for each online & visible buddy added to the feedbag.
// Sends buddy arrival notifications to each unblocked buddy if current user is
// visible. It returns wire.FeedbagStatus, which contains update confirmation.
func (s FeedbagService) DeleteItem(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (wire.SNACMessage, error) {
	if err := s.feedbagManager.FeedbagDelete(ctx, sess.IdentScreenName(), inBody.Items); err != nil {
		return wire.SNACMessage{}, err
	}

	var filter []state.IdentScreenName

	for _, item := range inBody.Items {
		switch item.ClassID {
		case wire.FeedbagClassIdBuddy, wire.FeedbagClassIDDeny, wire.FeedbagClassIDPermit:
			filter = append(filter, state.NewIdentScreenName(item.Name))
		}
	}

	if err := s.buddyBroadcaster.BroadcastVisibility(ctx, sess, filter, true); err != nil {
		return wire.SNACMessage{}, err
	}

	snacPayloadOut := wire.SNAC_0x13_0x0E_FeedbagStatus{}
	for range inBody.Items {
		snacPayloadOut.Results = append(snacPayloadOut.Results, 0x0000) // success by default
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagStatus,
			RequestID: inFrame.RequestID,
		},
		Body: snacPayloadOut,
	}, nil
}

// StartCluster exists to capture the SNAC input in unit tests to verify it's
// correctly unmarshalled.
func (s FeedbagService) StartCluster(context.Context, wire.SNACFrame, wire.SNAC_0x13_0x11_FeedbagStartCluster) {
}

// Use sends a user the contents of their buddy list. It's invoked at sign-on
// by AIM clients that use the feedbag food group for buddy list management (as
// opposed to client-side management).
func (s FeedbagService) Use(ctx context.Context, sess *state.Session) error {
	if err := s.feedbagManager.UseFeedbag(ctx, sess.IdentScreenName()); err != nil {
		return fmt.Errorf("could not use feedbag: %w", err)
	}
	items, err := s.feedbagManager.Feedbag(ctx, sess.IdentScreenName())
	if err != nil {
		return fmt.Errorf("feedbagManager.Feedbag: %w", err)
	}
	setSessionBuddyPrefs(items, sess)
	return nil
}

// RespondAuthorizeToHost forwards an authorization response from the user
// whose authorization was requested to the user who made the authorization
// request.
// Right now we send an ICBM request so that responses can work for both ICQ
// 2000b and ICQ 2001a. This function should eventually only send an ICBM
// message to non-feedbag clients and SNAC(0x0013,0x001B) to feedbag clients.
func (s FeedbagService) RespondAuthorizeToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost) error {
	response := wire.ICBMCh4Message{
		UIN:     sess.UIN(),
		Message: inBody.Reason,
	}

	switch inBody.Accepted {
	case 0:
		response.MessageType = wire.ICBMMsgTypeAuthDeny
	case 1:
		response.MessageType = wire.ICBMMsgTypeAuthOK
	default:
		return fmt.Errorf("invalid accepted flag %d", inBody.Accepted)
	}

	s.messageRelayer.RelayToScreenName(ctx, state.NewIdentScreenName(inBody.ScreenName), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
		},
		Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID:   wire.ICBMChannelICQ,
			TLVUserInfo: sess.TLVUserInfo(),
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVLE(wire.ICBMTLVData, response),
					wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
				},
			},
		},
	})

	return nil
}

// setSessionBuddyPrefs sets session preferences based on the feedbag buddy prefs item, if present.
func setSessionBuddyPrefs(items []wire.FeedbagItem, sess *state.Session) {
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs && item.HasTag(wire.FeedbagAttributesBuddyPrefs) {
			buddyPrefs, _ := item.Uint32BE(wire.FeedbagAttributesBuddyPrefs)
			sess.SetTypingEventsEnabled(buddyPrefs&wire.FeedbagBuddyPrefsWantsTypingEvents == wire.FeedbagBuddyPrefsWantsTypingEvents)
			break
		}
	}
}
