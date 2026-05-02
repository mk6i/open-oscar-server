package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewFeedbagService creates a new instance of FeedbagService.
func NewFeedbagService(
	logger *slog.Logger,
	messageRelayer MessageRelayer,
	feedbagManager FeedbagManager,
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	contactPreAuthorizer ContactPreAuthorizer,
	userManager UserManager,
) *FeedbagService {
	return &FeedbagService{
		bartItemManager:      bartItemManager,
		buddyBroadcaster:     newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		feedbagManager:       feedbagManager,
		logger:               logger,
		messageRelayer:       messageRelayer,
		relationshipFetcher:  relationshipFetcher,
		sessionRetriever:     sessionRetriever,
		contactPreAuthorizer: contactPreAuthorizer,
		userManager:          userManager,
		icbmSender: func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
			return nil, errors.New("icbmSender not implemented")
		},
	}
}

// FeedbagService provides functionality for the Feedbag food group, which
// handles buddy list management.
type FeedbagService struct {
	bartItemManager      BARTItemManager
	buddyBroadcaster     buddyBroadcaster
	feedbagManager       FeedbagManager
	logger               *slog.Logger
	messageRelayer       MessageRelayer
	relationshipFetcher  RelationshipFetcher
	sessionRetriever     SessionRetriever
	contactPreAuthorizer ContactPreAuthorizer
	userManager          UserManager
	icbmSender           func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
}

// BridgeICBMService enables the FeedbagService to send instant messages via the
// ICBM service.
func (s *FeedbagService) BridgeICBMService(service *ICBMService) {
	s.icbmSender = service.ChannelMsgToHost
}

// RightsQuery returns SNAC wire.FeedbagRightsReply, which contains Feedbag
// food group settings for the current user. The values within the SNAC are not
// well understood but seem to make the AIM client happy.
func (s *FeedbagService) RightsQuery(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
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
func (s *FeedbagService) Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error) {
	fb, err := s.feedbagManager.Feedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}

	lm := time.UnixMilli(0)

	if len(fb) > 0 {
		lm, err = s.feedbagManager.FeedbagLastModified(ctx, instance.IdentScreenName())
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
func (s *FeedbagService) QueryIfModified(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x05_FeedbagQueryIfModified) (wire.SNACMessage, error) {
	fb, err := s.feedbagManager.Feedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}

	lm := time.UnixMilli(0)

	if len(fb) > 0 {
		lm, err = s.feedbagManager.FeedbagLastModified(ctx, instance.IdentScreenName())
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
func (s *FeedbagService) UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, items []wire.FeedbagItem) (*wire.SNACMessage, error) {
	for _, item := range items {
		// don't let users block themselves, it causes the AIM client to go
		// into a weird state.
		if item.ClassID == wire.FeedbagClassIDDeny && state.NewIdentScreenName(item.Name) == instance.IdentScreenName() {
			return &wire.SNACMessage{
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

	// Check which buddy items require authorization. Items that need auth
	// are NOT inserted into the feedbag — the client must retry with the
	// FeedbagAttributesPending flag after receiving error 0x000E.
	var toUpsert []wire.FeedbagItem
	authRequired := make(map[string]bool)

	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy && !item.HasTag(wire.FeedbagAttributesPending) {
			sn := state.NewIdentScreenName(item.Name)
			switch {
			case instance.UIN() != 0 && sn.UIN() == 0: // sender=icq, recip=aim
				if err := s.contactPreAuthorizer.RecordPreAuth(ctx, instance.IdentScreenName(), sn); err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RecordPreAuth: %w", err)
				}
			case instance.UIN() != 0 && sn.UIN() != 0: // sender=icq, recip=icq
				blocked, err := s.contactPreAuthorizer.RequiresAuthorization(ctx, sn, instance.IdentScreenName())
				if err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RequiresAuthorization: %w", err)
				}
				if blocked {
					authRequired[item.Name] = true
					continue
				}
			case instance.UIN() == 0 && sn.UIN() != 0: // sender=aim, recip=icq
				blocked, err := s.contactPreAuthorizer.RequiresAuthorization(ctx, sn, instance.IdentScreenName())
				if err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RequiresAuthorization: %w", err)
				}
				if blocked {
					item.Append(wire.NewTLVLE(wire.FeedbagAttributesPending, []byte{}))
					if err := s.sendLegacyAuthReq(ctx, instance, sn, "", state.ICQBasicInfo{}, 1); err != nil {
						return nil, fmt.Errorf("sendLegacyAuthReq: %w", err)
					}
				}
			}
		}
		toUpsert = append(toUpsert, item)
	}

	if len(toUpsert) > 0 {
		if err := s.feedbagManager.FeedbagUpsert(ctx, instance.IdentScreenName(), toUpsert); err != nil {
			return nil, err
		}
	}

	setSessionBuddyPrefs(items, instance)

	snacPayloadOut := wire.SNAC_0x13_0x0E_FeedbagStatus{}
	for _, item := range items {
		if authRequired[item.Name] {
			snacPayloadOut.Results = append(snacPayloadOut.Results, 0x000E)
		} else {
			snacPayloadOut.Results = append(snacPayloadOut.Results, 0x0000)
		}
	}

	s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagStatus,
			RequestID: inFrame.RequestID,
		},
		Body: snacPayloadOut,
	})

	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: inFrame.FoodGroup,
			SubGroup:  inFrame.SubGroup,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
			Items: toUpsert,
		},
	})

	var filter []state.IdentScreenName
	var alertAll bool
	for _, item := range toUpsert {
		switch item.ClassID {
		case wire.FeedbagClassIdBuddy, wire.FeedbagClassIDPermit, wire.FeedbagClassIDDeny:
			filter = append(filter, state.NewIdentScreenName(item.Name))
		case wire.FeedbagClassIdBart:
			if err := s.setBARTItem(ctx, instance, item); err != nil {
				return nil, err
			}
		case wire.FeedbagClassIdPdinfo:
			alertAll = true
		}
	}

	// send ICQ "you were added" messages
	for _, item := range toUpsert {
		if item.ClassID == wire.FeedbagClassIdBuddy && !item.HasTag(wire.FeedbagAttributesPending) {
			user := state.NewIdentScreenName(item.Name)
			if user.UIN() != 0 {
				if fromSess := s.sessionRetriever.RetrieveSession(user); fromSess != nil && fromSess.UsesFeedbag() {
					s.messageRelayer.RelayToScreenName(ctx, user, wire.SNACMessage{
						Frame: wire.SNACFrame{
							FoodGroup: wire.Feedbag,
							SubGroup:  wire.FeedbagBuddyAdded,
							Flags:     0x8000,
						},
						Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
							TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
							ScreenName: instance.DisplayScreenName().String(),
						},
					})
				} else {
					if err := s.sendLegacyBuddyAddedMsg(ctx, instance, user); err != nil {
						return nil, fmt.Errorf("sendLegacyBuddyAddedMsg: %w", err)
					}
				}
			}
		}
	}

	if alertAll || len(filter) > 0 {
		if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, filter, true); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// setBARTItem informs clients about buddy icon update. If the BART
// store doesn't have the icon, then tell the client to upload the buddy icon.
// If the icon already exists, tell the user's buddies about the icon change.
func (s *FeedbagService) setBARTItem(ctx context.Context, instance *state.SessionInstance, item wire.FeedbagItem) error {
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
			instance.Session().SetBuddyIcon(bartID)
			// tell buddies about the icon update
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
				return err
			}
		}
		s.logger.DebugContext(ctx, "icon already exists in BART store, don't upload the icon file",
			"hash", fmt.Sprintf("%x", bartID.Hash))
	} else {
		// icon doesn't exist, tell the client to upload buddy icon
		bartID.Flags |= wire.BARTFlagsUnknown
		if bartID.Type == wire.BARTTypesBuddyIconSmall || bartID.Type == wire.BARTTypesBuddyIcon {
			instance.Session().SetBuddyIcon(bartID)
		}
		s.logger.DebugContext(ctx, "icon doesn't exist in BART store, client must upload the icon file",
			"hash", fmt.Sprintf("%x", bartID.Hash))
	}

	s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceBartReply,
		},
		Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
			BARTID: bartID,
		},
	})

	if bartID.Type == wire.BARTTypesBuddyIconSmall || bartID.Type == wire.BARTTypesBuddyIcon {
		s.messageRelayer.RelayToScreenName(ctx, instance.IdentScreenName(), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceUserInfoUpdate,
			},
			Body: newOServiceUserInfoUpdate(instance),
		})
	}

	return nil
}

// DeleteItem removes items from feedbag (aka buddy list). Sends user buddy
// arrival notifications for each online & visible buddy added to the feedbag.
// Sends buddy arrival notifications to each unblocked buddy if current user is
// visible. It returns wire.FeedbagStatus, which contains update confirmation.
func (s *FeedbagService) DeleteItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (*wire.SNACMessage, error) {
	if err := s.feedbagManager.FeedbagDelete(ctx, instance.IdentScreenName(), inBody.Items); err != nil {
		return nil, err
	}

	snacPayloadOut := wire.SNAC_0x13_0x0E_FeedbagStatus{}
	for range inBody.Items {
		snacPayloadOut.Results = append(snacPayloadOut.Results, 0x0000) // success by default
	}

	s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagStatus,
			RequestID: inFrame.RequestID,
		},
		Body: snacPayloadOut,
	})

	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: inFrame.FoodGroup,
			SubGroup:  inFrame.SubGroup,
			RequestID: wire.ReqIDFromServer,
		},
		Body: inBody,
	})

	var filter []state.IdentScreenName

	for _, item := range inBody.Items {
		switch item.ClassID {
		case wire.FeedbagClassIdBuddy, wire.FeedbagClassIDDeny, wire.FeedbagClassIDPermit:
			filter = append(filter, state.NewIdentScreenName(item.Name))
		}
	}

	if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, filter, true); err != nil {
		return nil, err
	}

	return nil, nil
}

// StartCluster signals the beginning of a batch of feedbag operations that clients should
// process together to prevent UI flicker during rapid updates. It transmits the start message
// to other session instances.
func (s *FeedbagService) StartCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x11_FeedbagStartCluster) {
	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: inFrame,
		Body:  inBody,
	})
}

// EndCluster signals the completion of a batched feedbag operation group. It transmits the end
// message to other session instances.
func (s *FeedbagService) EndCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) {
	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: inFrame,
		Body:  wire.SNAC_0x13_0x12_FeedbagEndCluster{},
	})
}

// Use sends a user the contents of their buddy list. It's invoked at sign-on
// by AIM clients that use the feedbag food group for buddy list management (as
// opposed to client-side management).
func (s *FeedbagService) Use(ctx context.Context, instance *state.SessionInstance) error {
	if err := s.feedbagManager.UseFeedbag(ctx, instance.IdentScreenName()); err != nil {
		return fmt.Errorf("could not use feedbag: %w", err)
	}
	items, err := s.feedbagManager.Feedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return fmt.Errorf("feedbagManager.Feedbag: %w", err)
	}
	setSessionBuddyPrefs(items, instance)
	instance.Session().SetUsesFeedbag()
	return nil
}

// RequestAuthorizeToHost forwards an authorization request from the user who
// wants to add a contact to the contact being added. If the recipient session
// uses feedbag this sign-on, they receive SNAC(0x13,0x19); otherwise a
// synthetic SNAC(0x04,0x06) ICBM channel message to host (ICQ ch4 auth req)
// is relayed to the recipient via messageRelayer.
func (s *FeedbagService) RequestAuthorizeToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost) error {
	recipient := state.NewIdentScreenName(inBody.ScreenName)
	recipSess := s.sessionRetriever.RetrieveSession(recipient)
	useFeedbag := recipSess != nil && recipSess.UsesFeedbag()

	if useFeedbag {
		s.messageRelayer.RelayToScreenName(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRequestAuthorizeToClient,
			},
			Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
				ScreenName: instance.IdentScreenName().String(),
				Reason:     inBody.Reason,
			},
		})
		return nil
	}

	// if authorized, the recipient can reciprocate without requesting authorization
	authorized := 1
	blocked, err := s.contactPreAuthorizer.RequiresAuthorization(ctx, instance.IdentScreenName(), recipient)
	if err != nil {
		return fmt.Errorf("contactPreAuthorizer.RequiresAuthorization: %w", err)
	}
	if blocked {
		authorized = 0
	}

	var userInfo state.User
	if user, err := s.userManager.User(ctx, instance.IdentScreenName()); err != nil {
		return fmt.Errorf("userManager.User: %w", err)
	} else if user != nil {
		userInfo = *user
	} else {
		s.logger.ErrorContext(ctx, "user not found", "screen_name", instance.IdentScreenName())
	}

	return s.sendLegacyAuthReq(ctx, instance, recipient, inBody.Reason, userInfo.ICQBasicInfo, authorized)
}

// sendLegacyAuthReq sends an offline authorization request to ICQ client
func (s *FeedbagService) sendLegacyAuthReq(ctx context.Context, from *state.SessionInstance, to state.IdentScreenName, reason string, userInfo state.ICQBasicInfo, authorized int) error {
	frame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
	}
	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelICQ,
		ScreenName: to.String(),
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN:         from.UIN(),
					MessageType: wire.ICBMMsgTypeAuthReq,
					Message: fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%d\xFE%s",
						userInfo.Nickname,
						userInfo.FirstName,
						userInfo.LastName,
						userInfo.EmailAddress,
						authorized,
						utf8ToLatin1(reason)),
				}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			},
		},
	}

	if _, err := s.icbmSender(ctx, from, frame, snac); err != nil {
		return fmt.Errorf("icbmSender: %w", err)
	}
	return nil
}

// PreAuthorizeBuddy handles SNAC(0x13,0x14) FEEDBAG__PRE_AUTHORIZE_BUDDY. The client
// pre-authorizes a buddy they just added so that user may add them later without
// an authorization prompt. Persists a contactPreauth row and may notify the buddy:
// SNAC(0x13,0x15) for online feedbag clients who do not block the sender; otherwise
// an ICQ channel-4 ICBM (auth granted) for offline or non-feedbag clients.
func (s *FeedbagService) PreAuthorizeBuddy(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy) (*wire.SNACMessage, error) {
	buddy := state.NewIdentScreenName(inBody.ScreenName)
	if buddy == instance.IdentScreenName() {
		return &wire.SNACMessage{
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

	if err := s.authorizeContact(ctx, instance.IdentScreenName(), state.NewIdentScreenName(inBody.ScreenName), inBody.Message); err != nil {
		return nil, fmt.Errorf("s.authorizeContact: %w", err)
	}

	return nil, nil
}

func utf8ToLatin1(s string) string {
	if isASCII(s) {
		return s
	}
	var result []byte
	for _, r := range s {
		if r <= 0xFF {
			result = append(result, byte(r))
		} else {
			result = append(result, '?')
		}
	}
	return string(result)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

func (s *FeedbagService) authorizeContact(ctx context.Context, from state.IdentScreenName, to state.IdentScreenName, message string) error {
	recipSess := s.sessionRetriever.RetrieveSession(to)

	if err := s.contactPreAuthorizer.RecordPreAuth(ctx, from, to); err != nil {
		if errors.Is(err, state.ErrNoUser) {
			s.logger.DebugContext(ctx, "user not found", "name", to.String())
			return nil
		}
		return fmt.Errorf("RecordPreAuth: %w", err)
	}

	if recipSess == nil {
		if err := s.sendLegacyAuthMsg(ctx, from, to); err != nil {
			return fmt.Errorf("sendLegacyAuthMsg: %w", err)
		}
		return nil
	}

	if cleared, err := s.clearPendingAuth(ctx, from, to); err != nil {
		return fmt.Errorf("clearPendingAuth: %w", err)
	} else if cleared {
		return nil
	}

	if recipSess.UsesFeedbag() {
		rel, err := s.relationshipFetcher.Relationship(ctx, from, to)
		if err != nil {
			return fmt.Errorf("relationshipFetcher.Relationship: %w", err)
		}
		if rel.BlocksYou {
			return nil
		}
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagPreAuthorizedBuddy,
			},
			Body: wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy{
				ScreenName: from.String(),
				Message:    message,
				Flags:      0,
			},
		})
		return nil
	}

	// send legacy ICQ authorization message
	if err := s.sendLegacyAuthMsg(ctx, from, to); err != nil {
		return fmt.Errorf("sendLegacyAuthMsg: %w", err)
	}

	return nil
}

func (s *FeedbagService) sendLegacyAuthMsg(ctx context.Context, from state.IdentScreenName, to state.IdentScreenName) error {
	// send offline "auth granted" message
	frame := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	body := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     uint64(time.Now().UnixNano()),
		ChannelID:  wire.ICBMChannelICQ,
		ScreenName: to.String(),
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN:         from.UIN(),
					MessageType: wire.ICBMMsgTypeAuthOK,
				}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			},
		},
	}
	fromSess := state.NewSession()
	fromSess.SetIdentScreenName(from)
	fromSess.SetDisplayScreenName(state.DisplayScreenName(from.String()))
	if _, err := s.icbmSender(ctx, fromSess.AddInstance(), frame, body); err != nil {
		return err
	}
	return nil
}

// sendLegacyBuddyAddedMsg notifies from via a legacy ICQ channel-4 message
// that to has added them to their contact list.
func (s *FeedbagService) sendLegacyBuddyAddedMsg(ctx context.Context, from *state.SessionInstance, to state.IdentScreenName) error {
	frame := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	body := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     uint64(time.Now().UnixNano()),
		ChannelID:  wire.ICBMChannelICQ,
		ScreenName: to.String(),
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN:         from.UIN(),
					MessageType: wire.ICBMMsgTypeAdded,
				}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			},
		},
	}
	if _, err := s.icbmSender(ctx, from, frame, body); err != nil {
		return err
	}
	return nil
}

func (s *FeedbagService) clearPendingAuth(ctx context.Context, from state.IdentScreenName, to state.IdentScreenName) (bool, error) {
	items, err := s.feedbagManager.Feedbag(ctx, to)
	if err != nil {
		return false, fmt.Errorf("failed to fetch feedbag items: %w", err)
	}

	// look for the pending buddy authorization
	var buddyItem *wire.FeedbagItem
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy && item.Name == from.String() {
			buddyItem = &item
			break
		}
	}

	// pending buddy authorization is not found, nothing to do
	if buddyItem == nil || !buddyItem.HasTag(wire.FeedbagAttributesPending) {
		return false, nil
	}
	// remove the pending buddy authorization tag
	buddyItem.TLVList = slices.DeleteFunc(buddyItem.TLVList, func(tlv wire.TLV) bool {
		return tlv.Tag == wire.FeedbagAttributesPending
	})

	updates := []wire.FeedbagItem{*buddyItem}
	if err = s.feedbagManager.FeedbagUpsert(ctx, to, updates); err != nil {
		return false, fmt.Errorf("failed to update feedbag: %w", err)
	}

	fromSess := s.sessionRetriever.RetrieveSession(from)
	if fromSess != nil && fromSess.UsesFeedbag() {
		s.messageRelayer.RelayToScreenName(ctx, from, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagBuddyAdded,
				Flags:     0x8000,
			},
			Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
				TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
				ScreenName: to.String(),
			},
		})
	} else {
		toSess := state.NewSession()
		toSess.SetIdentScreenName(to)
		toSess.SetDisplayScreenName(state.DisplayScreenName(to.String()))
		if err := s.sendLegacyBuddyAddedMsg(ctx, toSess.AddInstance(), from); err != nil {
			return false, fmt.Errorf("sendLegacyBuddyAddedMsg: %w", err)
		}
	}

	// clear the pending flag on the recipient's buddy entry
	s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagUpdateItem,
			Flags:     0x8000,
		},
		Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
			Items: updates,
		},
	})

	// tell the recipient that we're friends
	s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRespondAuthorizeToClient,
			Flags:     0x8000,
		},
		Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
			TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
			ScreenName: from.String(),
			Accepted:   1,
		},
	})

	if fromSess != nil {
		instances := fromSess.Instances()
		if len(instances) > 0 {
			// tell the recipient that we're online
			if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instances[0], []state.IdentScreenName{to}, false); err != nil {
				s.logger.ErrorContext(ctx, "broadcastBuddyArrived failed", "err", err)
			}
		}
	}

	return true, nil
}

// RespondAuthorizeToHost forwards an authorization response from the user
// whose authorization was requested to the user who made the authorization
// request.
// Right now we send an ICBM request so that responses can work for both ICQ
// 2000b and ICQ 2001a. This function should eventually only send an ICBM
// message to non-feedbag clients and SNAC(0x0013,0x001B) to feedbag clients.
func (s *FeedbagService) RespondAuthorizeToHost(ctx context.Context, instance state.IdentScreenName, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost) error {
	switch inBody.Accepted {
	case 0:
		err := s.rejectContact(ctx, instance, state.NewIdentScreenName(inBody.ScreenName), inBody.Reason)
		if err != nil {
			return err
		}
	case 1:
		if err := s.authorizeContact(ctx, instance, state.NewIdentScreenName(inBody.ScreenName), inBody.Reason); err != nil {
			return fmt.Errorf("s.authorizeContact: %w", err)
		}
	default:
		return fmt.Errorf("invalid accepted flag %d", inBody.Accepted)
	}

	return nil
}

func (s *FeedbagService) rejectContact(ctx context.Context, from state.IdentScreenName, to state.IdentScreenName, reason string) error {
	if toSess := s.sessionRetriever.RetrieveSession(to); toSess != nil && toSess.UsesFeedbag() {
		s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRespondAuthorizeToClient,
				Flags:     0x8000,
			},
			Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
				TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
				ScreenName: from.String(),
				Accepted:   0,
				Reason:     reason,
			},
		})
	} else {
		frame := wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToHost,
		}
		snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:  wire.ICBMChannelICQ,
			ScreenName: to.String(),
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
						UIN:         from.UIN(),
						MessageType: wire.ICBMMsgTypeAuthDeny,
						Message:     reason,
					}),
					wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
				},
			},
		}
		fromSess := state.NewSession()
		fromSess.SetIdentScreenName(from)
		fromSess.SetDisplayScreenName(state.DisplayScreenName(from.String()))
		if _, err := s.icbmSender(ctx, fromSess.AddInstance(), frame, snac); err != nil {
			return fmt.Errorf("could not send ICBM message: %w", err)
		}
	}

	return nil
}

// setSessionBuddyPrefs sets session preferences based on the feedbag buddy prefs item, if present.
func setSessionBuddyPrefs(items []wire.FeedbagItem, instance *state.SessionInstance) {
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs && item.HasTag(wire.FeedbagAttributesBuddyPrefs) {
			buddyPrefs, _ := item.Uint32BE(wire.FeedbagAttributesBuddyPrefs)
			instance.Session().SetTypingEventsEnabled(buddyPrefs&wire.FeedbagBuddyPrefsWantsTypingEvents == wire.FeedbagBuddyPrefsWantsTypingEvents)
			break
		}
	}
}

// FeedbagBuddyPref returns a pref value stored in the user's feedbag.
//
// Preferences are binary values stored in a logical bitmask spanning 2
// physical bitmasks. Each preference value is a position in the logical
// bitmask.
//
// The first bitmask (BuddyPrefs) is fixed-length of 32 bits (4 bytes).
// It's 0-offset: pref 1 is at offset 1, pref 2 at offset 2, etc. The most
// significant bit is on the right side.
//
// The second bitmask (BuddyPrefs2) is of an unbounded length. The values
// are at a position relative to the beginning at BuddyPrefs1. The most
// significant bit is on the left side.
//
// Items 1-31 are located in BuddyPrefs:
//
//	Item #1:
//	00000000 00000000 00000000 00000010 (BuddyPrefs)
//	                                 ^ offset 1, bit 2
//	00000000 00000000 00000000 00000000 (BuddyPrefs2)
//
//	Item #31:
//	10000000 00000000 00000000 00000000 (BuddyPrefs)
//	^ offset 31, bit 32
//	00000000 00000000 00000000 00000000 (BuddyPrefs2)
//
// Items 32+ are located in BuddyPrefs. To find the offset, calculate (Item #)-33.
// For example, item 52 is located at offset 19.
//
//	Item #52:
//	00000000 00000000 00000000 00000000 (BuddyPrefs)
//	00000000 00000000 00010000 00000000 (BuddyPrefs2)
//	                     ^ offset 19, bit 52
//
// There is a weird edge case for items 32 and 33 that is either a bug caused
// by the transition from offset to positional-based indexing, or a
// misunderstanding on my part: both items fall under offset 0 in BuddyPrefs2.
//
//	Item #32:
//	00000000 00000000 00000000 00000000 (BuddyPrefs)
//	10000000 00000000 00000000 00000000 (BuddyPrefs2)
//	^ offset 0, bit 33
//
//	Item #33:
//	00000000 00000000 00000000 00000000 (BuddyPrefs)
//	10000000 00000000 00000000 00000000 (BuddyPrefs2)
//	^ offset 0, bit 33
//
// For each logical bitmask, there are 2 physical bitmasks. The first contains
// the set values, and the second contains the valid bitmask positions. I guess
// this was done to remove ambiguity about an unset position: i.e. does an unset
// value mean false or null?
//
// The bitmasks are present in 4 TLVs:
//
// - 0x00C9: FeedbagAttributesBuddyPrefs
// - 0x00D6: FeedbagAttributesBuddyPrefsValid
// - 0x00D7: FeedbagAttributesBuddyPrefs2
// - 0x00D8: FeedbagAttributesBuddyPrefs2Valid
//
// For a given item, this function returns whether the preference number is
// available in the bitmask (valid) and what the value of it is (value).
func feedbagBuddyPref(prefNum uint16, list wire.TLVList) (valid bool, value bool) {
	offset := int(prefNum)

	// value is in BuddyPrefs; the most significant bit is on the right side
	if offset < 32 {
		buddyPrefValid, ok := list.Bytes(wire.FeedbagAttributesBuddyPrefsValid)
		if !ok {
			return false, false
		}
		buddyPrefEnabled, ok := list.Bytes(wire.FeedbagAttributesBuddyPrefs)
		if !ok {
			return false, false
		}

		index := (len(buddyPrefValid) - 1) - (offset / 8)
		if index >= len(buddyPrefValid) || index >= len(buddyPrefEnabled) {
			return false, false
		}

		bitOffset := offset % 8
		mask := byte(1 << bitOffset)

		valid = buddyPrefValid[index]&mask != 0
		value = buddyPrefEnabled[index]&mask != 0

		return valid, value
	}

	// value is in BuddyPrefs2; the most significant bit is on the left side
	if prefNum == 32 {
		offset = 0 // account for transition from offset-based to position-based
	} else {
		offset -= 33
	}

	buddyPrefValid, ok := list.Bytes(wire.FeedbagAttributesBuddyPrefs2Valid)
	if !ok {
		return false, false
	}
	buddyPrefEnabled, ok := list.Bytes(wire.FeedbagAttributesBuddyPrefs2)
	if !ok {
		return false, false
	}

	index := offset / 8
	if index >= len(buddyPrefValid) || index >= len(buddyPrefEnabled) {
		return false, false
	}

	bitOffset := offset % 8
	mask := byte(0x80) >> bitOffset

	valid = buddyPrefValid[index]&mask != 0
	value = buddyPrefEnabled[index]&mask != 0

	return valid, value
}

// ForwardICQAuthEvents converts ICQ channel-4 payloads to feedbag SNACs and
// sends them to feedbag-enabled recipient.
func (s *FeedbagService) ForwardICQAuthEvents(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error {
	switch authMsg.MessageType {
	case wire.ICBMMsgTypeAuthOK:
		msg := wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
			ScreenName: recipient.String(),
			Accepted:   1,
			Reason:     authMsg.Message,
		}
		return s.RespondAuthorizeToHost(ctx, sender, wire.SNACFrame{}, msg)
	case wire.ICBMMsgTypeAuthDeny:
		msg := wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
			ScreenName: recipient.String(),
			Accepted:   0,
			Reason:     authMsg.Message,
		}
		return s.RespondAuthorizeToHost(ctx, sender, wire.SNACFrame{}, msg)
	case wire.ICBMMsgTypeAdded:
		s.messageRelayer.RelayToScreenName(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagBuddyAdded,
				Flags:     0x8000,
			},
			Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
				TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
				ScreenName: sender.String(),
			},
		})
	case wire.ICBMMsgTypeAuthReq:
		reasonText := ""
		parts := strings.Split(authMsg.Message, "\xFE")
		if len(parts) >= 6 {
			reasonText = parts[5]
		}
		s.messageRelayer.RelayToScreenName(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRequestAuthorizeToClient,
				Flags:     0x8000,
			},
			Body: wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
				TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
				ScreenName: sender.String(),
				Reason:     reasonText,
			},
		})
	default:
		s.logger.WarnContext(ctx, "unknown authMsg ICBM message type", "type", authMsg.MessageType)
	}

	return nil
}
