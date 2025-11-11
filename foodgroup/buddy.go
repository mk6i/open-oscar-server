package foodgroup

import (
	"context"
	"fmt"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// NewBuddyService creates a new instance of BuddyService.
func NewBuddyService(
	messageRelayer MessageRelayer,
	clientSideBuddyListManager ClientSideBuddyListManager,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	bartItemManager BARTItemManager,
) *BuddyService {
	return &BuddyService{
		buddyBroadcaster:           newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		clientSideBuddyListManager: clientSideBuddyListManager,
	}
}

// BuddyService provides functionality for the Buddy food group.
type BuddyService struct {
	clientSideBuddyListManager ClientSideBuddyListManager
	buddyBroadcaster           buddyBroadcaster
}

// RightsQuery returns buddy list service parameters.
func (s BuddyService) RightsQuery(_ context.Context, frameIn wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyRightsReply,
			RequestID: frameIn.RequestID,
		},
		Body: wire.SNAC_0x03_0x03_BuddyRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxBuddies, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxWatchers, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxIcqBroad, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxTempBuddies, uint16(100)),
				},
			},
		},
	}
}

// AddBuddies adds buddies to my client-side buddy list.
func (s BuddyService) AddBuddies(
	ctx context.Context,
	sess *state.Session,
	inBody wire.SNAC_0x03_0x04_BuddyAddBuddies,
) error {

	for _, entry := range inBody.Buddies {
		sn := state.NewIdentScreenName(entry.ScreenName)
		if err := s.clientSideBuddyListManager.AddBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
	}

	if !sess.SignonComplete() {
		// client has not completed sign-on sequence, so any arrival
		// messages sent at this point would be ignored by the client.
		return nil
	}

	var toNotify []state.IdentScreenName
	for _, entry := range inBody.Buddies {
		toNotify = append(toNotify, state.NewIdentScreenName(entry.ScreenName))
	}
	if err := s.buddyBroadcaster.BroadcastVisibility(ctx, sess, toNotify, true); err != nil {
		return fmt.Errorf("buddyBroadcaster.BroadcastVisibility: %w", err)
	}

	return nil
}

// DelBuddies deletes buddies from my client-side buddy list.
func (s BuddyService) DelBuddies(ctx context.Context, sess *state.Session, inBody wire.SNAC_0x03_0x05_BuddyDelBuddies) error {

	var toNotify []state.IdentScreenName

	for _, entry := range inBody.Buddies {
		sn := state.NewIdentScreenName(entry.ScreenName)
		if err := s.clientSideBuddyListManager.RemoveBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
		toNotify = append(toNotify, sn)
	}

	if err := s.buddyBroadcaster.BroadcastVisibility(ctx, sess, toNotify, true); err != nil {
		return fmt.Errorf("buddyBroadcaster.BroadcastVisibility: %w", err)
	}

	return nil
}

// BroadcastBuddyArrived broadcasts buddy arrival with custom user info (implements DepartureNotifier)
func (s BuddyService) BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error {
	return s.buddyBroadcaster.BroadcastBuddyArrived(ctx, screenName, userInfo)
}

func (s BuddyService) BroadcastBuddyDeparted(ctx context.Context, sess *state.Session) error {
	return s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, sess)
}

func newBuddyNotifier(
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	messageRelayer MessageRelayer,
	sessionRetriever SessionRetriever,
) buddyNotifier {
	return buddyNotifier{
		bartItemManager:     bartItemManager,
		relationshipFetcher: relationshipFetcher,
		messageRelayer:      messageRelayer,
		sessionRetriever:    sessionRetriever,
	}
}

// buddyNotifier centralizes logic for sending buddy arrival and departure
// notifications.
type buddyNotifier struct {
	bartItemManager     BARTItemManager
	relationshipFetcher RelationshipFetcher
	messageRelayer      MessageRelayer
	sessionRetriever    SessionRetriever
}

// BroadcastBuddyArrived sends the latest user info to the user's adjacent users.
// While updates are sent via the wire.BuddyArrived SNAC, the message is not
// only used to indicate the user coming online. It can also notify changes to
// buddy icons, warning levels, invisibility status, etc.
func (s buddyNotifier) BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error {
	users, err := s.relationshipFetcher.AllRelationships(ctx, screenName, nil)
	if err != nil {
		return err
	}

	var recipients []state.IdentScreenName
	for _, user := range users {
		if user.YouBlock || user.BlocksYou || !user.IsOnTheirList {
			continue
		}
		recipients = append(recipients, user.User)
	}

	s.messageRelayer.RelayToScreenNames(ctx, recipients, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyArrived,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: userInfo,
		},
	})

	return nil
}

func (s buddyNotifier) BroadcastBuddyDeparted(ctx context.Context, sess *state.Session) error {
	users, err := s.relationshipFetcher.AllRelationships(ctx, sess.IdentScreenName(), nil)
	if err != nil {
		return err
	}

	var recipients []state.IdentScreenName
	for _, user := range users {
		if user.YouBlock || user.BlocksYou || !user.IsOnTheirList {
			continue
		}
		recipients = append(recipients, user.User)
	}

	s.messageRelayer.RelayToScreenNames(ctx, recipients, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyDeparted,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{
				// don't include the TLV block, otherwise the AIM client fails
				// to process the block event
				ScreenName:   sess.IdentScreenName().String(),
				WarningLevel: sess.Warning(),
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						// this TLV needs to be set in order for departure
						// events to work in ICQ
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0)),
					},
				},
			},
		},
	})

	return nil
}

// BroadcastVisibility sends you and related users arrival/departure
// notifications that reflect your buddy list and privacy preferences.
//
// Behavior:
//   - Sends you arrival notifications for users on your buddy list that I do
//     not block.
//   - Sends arrival notifications to users that you block who have you on
//     their buddy lists.
//   - Sends you departure notifications for users on your buddy list that you
//     block  (if doSendDepartures is true).
//   - Sends departure notifications to users that you block who have you on
//     their buddy lists (if doSendDepartures is true).
//   - Don't send notifications for any user that blocks you.
//
// This method is called when your visibility settings change, ensuring that
// all relevant users are notified of your arrival or departure status.
func (s buddyNotifier) BroadcastVisibility(
	ctx context.Context,
	you *state.Session,
	filter []state.IdentScreenName,
	doSendDepartures bool,
) error {

	relationships, err := s.relationshipFetcher.AllRelationships(ctx, you.IdentScreenName(), filter)
	if err != nil {
		return fmt.Errorf("retrieving relationships: %w", err)
	}

	yourTLVInfo := you.TLVUserInfo()

	for _, relationship := range relationships {
		if relationship.BlocksYou {
			continue // they block you, don't send them notifications
		}

		theirSess := s.sessionRetriever.RetrieveSession(relationship.User)
		if theirSess == nil {
			continue // they are offline
		}

		if !relationship.YouBlock {
			if relationship.IsOnTheirList {
				// tell them you're online
				s.unicastBuddyArrived(ctx, yourTLVInfo, theirSess.IdentScreenName())
			}
			if relationship.IsOnYourList {
				theirInfo := theirSess.TLVUserInfo()
				// tell you they're online
				s.unicastBuddyArrived(ctx, theirInfo, you.IdentScreenName())
			}
		} else if relationship.YouBlock && doSendDepartures {
			if relationship.IsOnTheirList {
				// tell them you're offline
				s.unicastBuddyDeparted(ctx, you, theirSess.IdentScreenName())
			}
			if relationship.IsOnYourList {
				// tell you they're offline
				s.unicastBuddyDeparted(ctx, theirSess, you.IdentScreenName())
			}
		}
	}

	return nil
}

func (s buddyNotifier) unicastBuddyDeparted(ctx context.Context, from *state.Session, to state.IdentScreenName) {
	s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyDeparted,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{
				// don't include the TLV block, otherwise the AIM client fails
				// to process the block event
				ScreenName:   from.IdentScreenName().String(),
				WarningLevel: from.Warning(),
			},
		},
	})
}

// unicastBuddyArrived sends the latest user info to a particular user.
// While updates are sent via the wire.BuddyArrived SNAC, the message is not
// only used to indicate the user coming online. It can also notify changes to
// buddy icons, warning levels, invisibility status, etc.
func (s buddyNotifier) unicastBuddyArrived(ctx context.Context, userInfo wire.TLVUserInfo, to state.IdentScreenName) {
	s.messageRelayer.RelayToScreenName(ctx, to, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyArrived,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: userInfo,
		},
	})
}
