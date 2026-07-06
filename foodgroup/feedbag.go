package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	buddyAddedNotifierDeduper BuddyAddedNotifierDeduper,
) *FeedbagService {
	return &FeedbagService{
		bartItemManager:           bartItemManager,
		buddyBroadcaster:          newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		buddyAddedNotifierDeduper: buddyAddedNotifierDeduper,
		feedbagManager:            feedbagManager,
		logger:                    logger,
		messageRelayer:            messageRelayer,
		relationshipFetcher:       relationshipFetcher,
		sessionRetriever:          sessionRetriever,
		contactPreAuthorizer:      contactPreAuthorizer,
		userManager:               userManager,
		icbmSender: func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
			return nil, errors.New("icbmSender not implemented")
		},
	}
}

// FeedbagService provides functionality for the Feedbag food group, which
// handles buddy list management.
type FeedbagService struct {
	bartItemManager           BARTItemManager
	buddyBroadcaster          buddyBroadcaster
	buddyAddedNotifierDeduper BuddyAddedNotifierDeduper
	feedbagManager            FeedbagManager
	logger                    *slog.Logger
	messageRelayer            MessageRelayer
	relationshipFetcher       RelationshipFetcher
	sessionRetriever          SessionRetriever
	contactPreAuthorizer      ContactPreAuthorizer
	userManager               UserManager
	icbmSender                func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
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
	maxItemsByClass := make([]uint16, wire.FeedbagClassIdAlInfo+1)
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
	maxItemsByClass[wire.FeedbagClassIdAlInfo] = 4

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
		switch item.ClassID {
		case wire.FeedbagClassIDDeny:
			// don't let users block themselves, it causes the AIM client to go
			// into a weird state.
			if state.NewIdentScreenName(item.Name) == instance.IdentScreenName() {
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
		case wire.FeedbagClassIdAlInfo:
			// don't let users add arbitrary linked accounts. they can only be
			// added via the management API.
			return &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagErr,
					RequestID: inFrame.RequestID,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeInsufficientRights,
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
		if item.ClassID == wire.FeedbagClassIdAlInfo {
			continue
		}
		if item.ClassID == wire.FeedbagClassIdBuddy {
			sn := state.NewIdentScreenName(item.Name)
			switch {
			case instance.UIN() != 0 && sn.UIN() == 0:
				// sender: icq, recipient:aim
				// Automatically authorize AIM users when adding to ICQ buddy
				// list since AIM does not support the ICQ authorization flow.
				if err := s.contactPreAuthorizer.RecordPreAuth(ctx, instance.IdentScreenName(), sn); err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RecordPreAuth: %w", err)
				}
			case instance.UIN() != 0 && sn.UIN() != 0:
				// sender: icq, recipient:icq
				// Perform ICQ authorization flow.
				blocked, err := s.contactPreAuthorizer.RequiresAuthorization(ctx, sn, instance.IdentScreenName())
				if err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RequiresAuthorization: %w", err)
				}
				hasPending := item.HasTag(wire.FeedbagAttributesPending)
				if blocked && !hasPending {
					authRequired[item.Name] = true
					continue
				} else if hasPending && !blocked {
					// Authorization has since been granted (IServerd strips
					// SSI_TLV_AUTH before inserting when auth is already recorded).
					// Clear the pending flag so the row is stored as a normal buddy.
					item.Remove(wire.FeedbagAttributesPending)
				}
			case instance.UIN() == 0 && sn.UIN() != 0:
				// sender:aim, recipient: icq
				// Automatically request authorization on behalf of AIM user since
				// AIM does not support the ICQ authorization flow. The ICQ user
				// will appear offline until authorization is granted.
				blocked, err := s.contactPreAuthorizer.RequiresAuthorization(ctx, sn, instance.IdentScreenName())
				if err != nil {
					return nil, fmt.Errorf("contactPreAuthorizer.RequiresAuthorization: %w", err)
				}
				if blocked {
					item.Append(wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}))
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
			buddyScreenName := state.NewIdentScreenName(item.Name)
			if buddyScreenName.UIN() == 0 {
				continue // icq users only
			}

			// make sure this user hasn't already been notified
			alreadySent, err := s.buddyAddedNotifierDeduper.HasBuddyAddedNotification(ctx, instance.IdentScreenName(), buddyScreenName)
			if err != nil {
				return nil, fmt.Errorf("buddyAddedNotifierDeduper.HasBuddyAddedNotification: %w", err)
			}
			if alreadySent {
				continue
			}

			// they haven't been notified yet, record it for next time
			if err := s.buddyAddedNotifierDeduper.RecordBuddyAddedNotification(ctx, instance.IdentScreenName(), buddyScreenName); err != nil {
				return nil, fmt.Errorf("buddyAddedNotifierDeduper.RecordBuddyAddedNotification: %w", err)
			}

			buddySess := s.sessionRetriever.RetrieveSession(buddyScreenName)
			if buddySess != nil && buddySess.UsesFeedbag() {
				s.messageRelayer.RelayToScreenName(ctx, buddyScreenName, wire.SNACMessage{
					Frame: wire.SNACFrame{
						FoodGroup: wire.Feedbag,
						SubGroup:  wire.FeedbagBuddyAdded,
						Flags:     wire.SNACFlagsExtendedInfo,
					},
					Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
						TLVLBlock: wire.TLVLBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(4)),
							},
						},
						ScreenName: instance.DisplayScreenName().String(),
					},
				})
			} else {
				if err := s.sendLegacyBuddyAddedMsg(ctx, instance, buddyScreenName); err != nil {
					return nil, fmt.Errorf("sendLegacyBuddyAddedMsg: %w", err)
				}
			}
		}
	}

	if alertAll || len(filter) > 0 {
		if instance.InNotifyTxn() {
			if err := instance.NotifyTxn(filter...); err != nil {
				return nil, fmt.Errorf("NotifyTxn: %w", err)
			}
		} else {
			if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, filter, true); err != nil {
				return nil, err
			}
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

	if instance.InNotifyTxn() {
		if err := instance.NotifyTxn(filter...); err != nil {
			return nil, fmt.Errorf("NotifyTxn: %w", err)
		}
	} else {
		if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, filter, true); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// StartCluster signals the beginning of a batch of feedbag operations that clients should
// process together to prevent UI flicker during rapid updates. It transmits the start message
// to other session instances. It starts a new notification transaction, which records users
// that should receive presence notifications when the transaction ends.
func (s *FeedbagService) StartCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x11_FeedbagStartCluster) {
	instance.BeginNotifyTxn()
	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: inFrame,
		Body:  inBody,
	})
}

// EndCluster signals the completion of a batched feedbag operation group. It transmits the end
// message to other session instances. It broadcast presence notifications if any relevant
// changes accumulated during the transaction.
func (s *FeedbagService) EndCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) error {
	s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
		Frame: inFrame,
		Body:  wire.SNAC_0x13_0x12_FeedbagEndCluster{},
	})

	shouldNotify, filter := instance.EndNotifyTxn()
	if !shouldNotify {
		return nil
	}

	if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, filter, true); err != nil {
		return err
	}
	return nil
}

// Use activates server-side buddy list state for feedbag clients at sign-on.
// FeedbagUse and ClientOnline can arrive in either order; whichever handler runs
// second performs the initial buddy presence broadcast when both are satisfied.
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
	instance.SetContactsInit()

	// ICQ Lite order: ClientOnline before FeedbagUse — broadcast here.
	if instance.SignonComplete() {
		if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, nil, false); err != nil {
			return fmt.Errorf("buddyBroadcaster.BroadcastVisibility: %w", err)
		}
	}

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
		firstDot := strings.IndexByte(inBody.Reason, '.')
		if firstDot >= 0 {
			// ICQ 5 ignores authorization requests with multiple periods. Strip
			// all periods following the first so that the message arrives.
			inBody.Reason = inBody.Reason[:firstDot+1] + strings.ReplaceAll(inBody.Reason[firstDot+1:], ".", "")
		}
		s.messageRelayer.RelayToScreenName(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRequestAuthorizeToClient,
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
					},
				},
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

	return s.sendLegacyAuthReq(ctx, instance, recipient, inBody.Reason, userInfo.ICQInfo.Basic, authorized)
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

func (s *FeedbagService) authorizeContact(ctx context.Context, granter state.IdentScreenName, requester state.IdentScreenName, message string) error {
	requesterSess := s.sessionRetriever.RetrieveSession(requester)

	if err := s.contactPreAuthorizer.RecordPreAuth(ctx, granter, requester); err != nil {
		if errors.Is(err, state.ErrNoUser) {
			s.logger.DebugContext(ctx, "user not found", "name", requester.String())
			return nil
		}
		return fmt.Errorf("RecordPreAuth: %w", err)
	}

	if requesterSess == nil {
		if err := s.sendLegacyAuthMsg(ctx, granter, requester); err != nil {
			return fmt.Errorf("sendLegacyAuthMsg: %w", err)
		}
		return nil
	}

	if cleared, err := s.clearPendingAuth(ctx, granter, requester); err != nil {
		return fmt.Errorf("clearPendingAuth: %w", err)
	} else if cleared {
		return nil
	}

	if requesterSess.UsesFeedbag() {
		rel, err := s.relationshipFetcher.Relationship(ctx, granter, requester)
		if err != nil {
			return fmt.Errorf("relationshipFetcher.Relationship: %w", err)
		}
		if rel.BlocksYou {
			return nil
		}
		s.messageRelayer.RelayToScreenName(ctx, requester, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagPreAuthorizedBuddy,
			},
			Body: wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy{
				ScreenName: granter.String(),
				Message:    message,
				Flags:      0,
			},
		})
		return nil
	}

	// send legacy ICQ authorization message
	if err := s.sendLegacyAuthMsg(ctx, granter, requester); err != nil {
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

func (s *FeedbagService) clearPendingAuth(ctx context.Context, granter state.IdentScreenName, requester state.IdentScreenName) (bool, error) {
	items, err := s.feedbagManager.Feedbag(ctx, requester)
	if err != nil {
		return false, fmt.Errorf("failed to fetch feedbag items: %w", err)
	}

	// look for the pending buddy authorization
	var buddyItem *wire.FeedbagItem
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddy && item.Name == granter.String() {
			buddyItem = &item
			break
		}
	}

	// pending buddy authorization is not found, nothing to do
	if buddyItem == nil || !buddyItem.HasTag(wire.FeedbagAttributesPending) {
		return false, nil
	}
	// remove the pending buddy authorization tag
	buddyItem.Remove(wire.FeedbagAttributesPending)

	updates := []wire.FeedbagItem{*buddyItem}
	if err = s.feedbagManager.FeedbagUpsert(ctx, requester, updates); err != nil {
		return false, fmt.Errorf("failed to update feedbag: %w", err)
	}

	// send a "you were added" message to the granter
	granterSess := s.sessionRetriever.RetrieveSession(granter)
	if granterSess != nil && granterSess.UsesFeedbag() {
		s.messageRelayer.RelayToScreenName(ctx, granter, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagBuddyAdded,
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(4)),
					},
				},
				ScreenName: requester.String(),
			},
		})
	} else {
		requesterSess := state.NewSession()
		requesterSess.SetIdentScreenName(requester)
		requesterSess.SetDisplayScreenName(state.DisplayScreenName(requester.String()))
		requesterSess.SetUIN(requester.UIN())
		if err := s.sendLegacyBuddyAddedMsg(ctx, requesterSess.AddInstance(), granter); err != nil {
			return false, fmt.Errorf("sendLegacyBuddyAddedMsg: %w", err)
		}
	}

	// clear the pending flag on the requester's buddy entry
	s.messageRelayer.RelayToScreenName(ctx, requester, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagUpdateItem,
		},
		Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
			Items: updates,
		},
	})

	// tell the requester that we're friends
	s.messageRelayer.RelayToScreenName(ctx, requester, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRespondAuthorizeToClient,
			Flags:     wire.SNACFlagsExtendedInfo,
		},
		Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
				},
			},
			ScreenName: granter.String(),
			Accepted:   1,
		},
	})

	if granterSess != nil {
		instances := granterSess.Instances()
		if len(instances) > 0 {
			// tell the granter that we're online
			if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instances[0], []state.IdentScreenName{requester}, false); err != nil {
				s.logger.ErrorContext(ctx, "broadcastBuddyArrived failed", "err", err)
			}
		}
	}

	return true, nil
}

// RespondAuthorizeToHost forwards an authorization response from the user
// whose authorization was requested (granter) to the user who made the
// authorization request (requester).
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

func (s *FeedbagService) rejectContact(ctx context.Context, rejecter state.IdentScreenName, requester state.IdentScreenName, reason string) error {
	if toSess := s.sessionRetriever.RetrieveSession(requester); toSess != nil && toSess.UsesFeedbag() {
		s.messageRelayer.RelayToScreenName(ctx, requester, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagRespondAuthorizeToClient,
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
					},
				},
				ScreenName: rejecter.String(),
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
			ScreenName: requester.String(),
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
						UIN:         rejecter.UIN(),
						MessageType: wire.ICBMMsgTypeAuthDeny,
						Message:     reason,
					}),
					wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
				},
			},
		}
		fromSess := state.NewSession()
		fromSess.SetIdentScreenName(rejecter)
		fromSess.SetDisplayScreenName(state.DisplayScreenName(rejecter.String()))
		if _, err := s.icbmSender(ctx, fromSess.AddInstance(), frame, snac); err != nil {
			return fmt.Errorf("could not send ICBM message: %w", err)
		}
	}

	return nil
}

// setSessionBuddyPrefs sets session preferences based on the feedbag buddy prefs item, if present.
func setSessionBuddyPrefs(items []wire.FeedbagItem, instance *state.SessionInstance) {
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs {
			_, wantsTyping := wire.BuddyPref(item.TLVList, wire.FeedbagBuddyPrefsDiscloseTyping)
			instance.Session().SetTypingEventsEnabled(wantsTyping)
			break
		}
	}
}

// feedbagBuddyPref returns whether preference prefNum is present in the user's
// feedbag buddy-prefs bitmask (valid) and its boolean value. See wire.BuddyPref
// for the bitmask layout.
func feedbagBuddyPref(prefNum uint16, list wire.TLVList) (valid bool, value bool) {
	return wire.BuddyPref(list, prefNum)
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
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(4)),
					},
				},
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
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagTLVVersion, uint16(2)),
					},
				},
				ScreenName: sender.String(),
				Reason:     reasonText,
			},
		})
	default:
		s.logger.WarnContext(ctx, "unknown authMsg ICBM message type", "type", authMsg.MessageType)
	}

	return nil
}
