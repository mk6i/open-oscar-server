package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// blankGIF is a transparent GIF served for a cleared buddy icon. This GIF
	// composition approximates the real one based on observed client behavior:
	//   - QIP 2005 fails to decode a GIF whose image data ends before the last
	//     pixel, so the image data covers every pixel.
	//   - QIP 2005 doesn't erase behind a transparent icon that fills its 46x46
	//     display, so the icon is 44x44.
	//   - Pidgin discards a 90-byte icon and shows no icon, so this GIF is 90
	//     bytes.
	blankGIF = []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x2c, 0x00, 0x2c, 0x00, 0x81, 0x00, 0x00, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0xc0, 0xc0, 0xc0, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x2c, 0x00, 0x00, 0x02, 0x2b, 0x84, 0x8f, 0xa9,
		0xcb, 0xed, 0x0f, 0xa3, 0x9c, 0xb4, 0xda, 0x8b, 0xb3, 0xde, 0xbc, 0xfb, 0x0f, 0x86, 0xe2, 0x48,
		0x96, 0xe6, 0x89, 0xa6, 0xea, 0xca, 0xb6, 0xee, 0x0b, 0xc7, 0xf2, 0x4c, 0xd7, 0xf6, 0x8d, 0xe7,
		0xfa, 0xce, 0xf7, 0xfe, 0x0f, 0x0c, 0xc6, 0x0a, 0x00, 0x3b,
	}

	blankGIFHash = md5.Sum(blankGIF)

	blankGIFBARTItem = wire.BARTID{
		Type: wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{
			Flags: wire.BARTFlagsCustom,
			Hash:  blankGIFHash[:],
		},
	}
)

func NewBARTService(
	logger *slog.Logger,
	bartItemManager BARTItemManager,
	messageRelayer MessageRelayer,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
) BARTService {
	return BARTService{
		bartItemManager:        bartItemManager,
		buddyUpdateBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:         messageRelayer,
		logger:                 logger,
	}
}

type BARTService struct {
	bartItemManager        BARTItemManager
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

	bartID := wire.BARTID{
		Type: inBody.Type,
		BARTInfo: wire.BARTInfo{
			Flags: wire.BARTFlagsCustom,
			Hash:  hash,
		},
	}

	if bartID.IsBuddyIcon() {
		if err := s.updateBuddyIcon(ctx, instance, bartID); err != nil {
			return wire.SNACMessage{}, err
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

func (s BARTService) updateBuddyIcon(ctx context.Context, instance *state.SessionInstance, newID wire.BARTID) error {
	curID, hasIcon := instance.Session().BuddyIcon()

	if hasIcon && bytes.Equal(curID.Hash, newID.Hash) {
		// client set icon metadata in prior FeedbagService call before upload
		if err := setBuddyIconState(ctx, instance, newID, s.buddyUpdateBroadcaster, s.messageRelayer); err != nil {
			return err
		}
	} else {
		// client uploads buddy icon now and sets icon metadata in subsequent
		// call to FeedbagService
		s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceBartReply,
			},
			Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
				BARTID: newID,
			},
		})
	}

	return nil
}

// RetrieveItem fetches a BART item from the data store. The item is selected
// based on inBody.Hash. It's unclear what effect inBody.Flags is supposed to
// have on the request.
func (s BARTService) RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error) {
	var item []byte
	if inBody.IsBuddyIcon() && (inBody.HasClearIconHash() || bytes.Equal(inBody.Hash, blankGIFHash[:])) {
		item = blankGIF
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

		if id.IsBuddyIcon() && (id.HasClearIconHash() || bytes.Equal(id.Hash, blankGIFHash[:])) {
			item = blankGIF
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

// setBuddyIconState sets bid as the session's buddy icon, then sends the
// updated user info to the user's instances and to their buddies.
func setBuddyIconState(ctx context.Context, instance *state.SessionInstance, bid wire.BARTID, buddyBroadcaster buddyBroadcaster, messageRelayer MessageRelayer) error {
	instance.Session().SetBuddyIcon(bid)

	sendUserInfoUpdateToAll(ctx, messageRelayer, instance)

	if err := buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
		return fmt.Errorf("BroadcastBuddyArrived: %w", err)
	}
	return nil
}
