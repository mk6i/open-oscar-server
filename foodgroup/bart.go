package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// blankGIF is a blank, transparent 50x50p GIF that takes the place of a
// cleared buddy icon.
var blankGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x32, 0x00, 0x32, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x00, 0x32, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// clearedIconData is served in place of a cleared buddy icon. QIP 2005 only
// replaces a cached icon after downloading a payload longer than 16 bytes that
// starts with an image signature. It deletes the cached icon files before
// decoding the new image and swallows the decode error, so a GIF signature
// followed by an invalid header leaves no icon file and QIP shows its
// built-in "no icon" image.
var clearedIconData = append([]byte("GIF89a"), make([]byte, 26)...)

// blankGIFHash is the MD5 hash of clearedIconData.
var blankGIFHash = func() []byte {
	h := md5.Sum(clearedIconData)
	return h[:]
}()

// blankBuddyIcon returns the BART ID sent to buddies in place of a cleared
// buddy icon. Some clients, such as QIP 2005, ignore the 5-byte clear icon
// hash and keep showing the cached icon, but they do replace it when the hash
// changes to a real 16-byte MD5 hash, so the server advertises blankGIF.
func blankBuddyIcon() wire.BARTID {
	return wire.BARTID{
		Type: wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{
			Flags: wire.BARTFlagsCustom,
			Hash:  blankGIFHash,
		},
	}
}

// blankIconData returns the payload served for a cleared icon hash.
func blankIconData(info wire.BARTInfo) ([]byte, bool) {
	switch {
	case info.HasClearIconHash():
		return blankGIF, true
	case bytes.Equal(info.Hash, blankGIFHash):
		return clearedIconData, true
	}
	return nil, false
}

func NewBARTService(
	logger *slog.Logger,
	bartItemManager BARTItemManager,
	messageRelayer MessageRelayer,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	feedbagManager FeedbagManager,
) BARTService {
	return BARTService{
		bartItemManager:        bartItemManager,
		feedbagManager:         feedbagManager,
		buddyUpdateBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:         messageRelayer,
		logger:                 logger,
	}
}

type BARTService struct {
	bartItemManager        BARTItemManager
	feedbagManager         FeedbagManager
	buddyUpdateBroadcaster buddyBroadcaster
	messageRelayer         MessageRelayer
	logger                 *slog.Logger
}

func (s BARTService) UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error) {
	h := md5.New()
	if _, err := h.Write(inBody.Data); err != nil {
		return wire.SNACMessage{}, err
	}
	hash := h.Sum(nil)

	if err := s.bartItemManager.InsertBARTItem(ctx, hash, inBody.Data, inBody.Type); err != nil {
		if !errors.Is(err, state.ErrBARTItemExists) {
			return wire.SNACMessage{}, fmt.Errorf("failed to insert BART item: %w", err)
		}
	}

	s.logger.DebugContext(ctx, "successfully uploaded BART item", "hash", fmt.Sprintf("%x", hash))

	bartID, hasIcon := instance.Session().BuddyIcon()
	if hasIcon && bytes.Equal(hash, bartID.Hash) {
		// unset unknown flag
		bartID.Flags &^= wire.BARTFlagsUnknown
		instance.Session().SetBuddyIcon(bartID)

		sendUserInfoUpdateToAll(ctx, s.messageRelayer, instance)

		if err := s.buddyUpdateBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
			return wire.SNACMessage{}, err
		}
	} else {
		bartID = wire.BARTID{
			Type: inBody.Type,
			BARTInfo: wire.BARTInfo{
				Flags: wire.BARTFlagsCustom,
				Hash:  hash,
			},
		}
		if inBody.Type == wire.BARTTypesBuddyIcon {
			if err := s.assignBuddyIcon(ctx, instance, bartID); err != nil {
				return wire.SNACMessage{}, err
			}
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BART,
			SubGroup:  wire.BARTUploadReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x10_0x03_BARTUploadReply{
			Code: wire.BARTReplyCodesSuccess,
			ID:   bartID,
		},
	}, nil
}

// RetrieveItem fetches a BART item from the data store. The item is selected
// based on inBody.Hash. It's unclear what effect inBody.Flags is supposed to
// have on the request.
func (s BARTService) RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error) {
	var item []byte
	if data, ok := blankIconData(inBody.BARTInfo); ok {
		item = data
	} else {
		var err error
		if item, err = s.bartItemManager.BARTItem(ctx, inBody.Hash); err != nil {
			return wire.SNACMessage{}, err
		}
	}

	// todo... how to reply if requested item doesn't exist
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BART,
			SubGroup:  wire.BARTDownloadReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{
			ScreenName: inBody.ScreenName,
			BARTID:     inBody.BARTID,
			Data:       item,
		},
	}, nil
}

// RetrieveItemV2 implements the SNAC handler for SNAC(0x10,0x06) BARTDownload2Query.
func (s BARTService) RetrieveItemV2(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x06_BARTDownload2Query) ([]wire.SNACMessage, error) {
	var result []wire.SNACMessage

	for _, id := range inBody.IDs {
		var item []byte

		if data, ok := blankIconData(id.BARTInfo); ok && id.Type == wire.BARTTypesBuddyIcon {
			item = data
		} else {
			var err error
			if item, err = s.bartItemManager.BARTItem(ctx, id.Hash); err != nil {
				return nil, err
			}
		}

		result = append(result, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BART,
				SubGroup:  wire.BARTDownload2Reply,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x10_0x07_BARTDownload2Reply{
				ScreenName: inBody.ScreenName,
				ReplyID: wire.BartQueryReplyID{
					QueryID: id,
					Code:    0x00, // found
					ReplyID: wire.BARTID{
						Type:     id.Type,
						BARTInfo: id.BARTInfo,
					},
				},
				Data: item,
			},
		})
	}

	return result, nil
}

// assignBuddyIcon makes an uploaded icon the user's buddy icon. Clients such
// as QIP 2005 upload the icon without first setting the feedbag BART item, so
// the server stores the item itself and notifies the user's buddies.
func (s BARTService) assignBuddyIcon(ctx context.Context, instance *state.SessionInstance, bartID wire.BARTID) error {
	items, err := s.feedbagManager.Feedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return fmt.Errorf("failed to fetch feedbag: %w", err)
	}

	name := strconv.Itoa(int(wire.BARTTypesBuddyIcon))
	item := wire.FeedbagItem{Name: name, ClassID: wire.FeedbagClassIdBart}
	used := make(map[uint16]bool)
	found := false
	for _, it := range items {
		if it.GroupID == 0 {
			used[it.ItemID] = true
		}
		if !found && it.ClassID == wire.FeedbagClassIdBart && it.Name == name {
			item.GroupID, item.ItemID = it.GroupID, it.ItemID
			found = true
		}
	}
	if !found {
		for item.ItemID = 1; used[item.ItemID]; item.ItemID++ {
		}
	}
	item.Append(wire.NewTLVBE(wire.FeedbagAttributesBartInfo, bartID.BARTInfo))

	if err := s.feedbagManager.FeedbagUpsert(ctx, instance.IdentScreenName(), []wire.FeedbagItem{item}); err != nil {
		return fmt.Errorf("failed to save BART feedbag item: %w", err)
	}

	instance.Session().SetBuddyIcon(bartID)
	s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceBartReply,
		},
		Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
			BARTID: bartID,
		},
	})
	sendUserInfoUpdateToAll(ctx, s.messageRelayer, instance)

	s.logger.DebugContext(ctx, "assigned uploaded icon as buddy icon", "hash", fmt.Sprintf("%x", bartID.Hash))

	return s.buddyUpdateBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo())
}
