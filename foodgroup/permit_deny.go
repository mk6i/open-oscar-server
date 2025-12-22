package foodgroup

import (
	"context"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewPermitDenyService creates an instance of PermitDenyService.
func NewPermitDenyService(
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	clientSideBuddyListManager ClientSideBuddyListManager,
	messageRelayer MessageRelayer,
	sessionRetriever SessionRetriever,
) PermitDenyService {
	return PermitDenyService{
		buddyBroadcaster:           newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		clientSideBuddyListManager: clientSideBuddyListManager,
	}
}

// PermitDenyService provides functionality for the PermitDeny (PD) food group.
// The PD food group manages settings for permit/deny (allow/block) for
// pre-feedbag (sever-side buddy list) AIM clients.
type PermitDenyService struct {
	buddyBroadcaster           buddyBroadcaster
	clientSideBuddyListManager ClientSideBuddyListManager
}

// AddDenyListEntries adds users to your block list and sets your visibility
// mode to "deny some". If your screen name is passed as a single element in
// the input payload, your visibility mode is set to "permit all" instead.
// Your buddy list and your relations' buddy lists are updated to reflect the
// current mode.
func (s PermitDenyService) AddDenyListEntries(
	ctx context.Context,
	sess *state.Session,
	body wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries,
) error {
	if len(body.Users) == 1 {
		sn := state.NewIdentScreenName(body.Users[0].ScreenName)
		if sn.String() == sess.IdentScreenName().String() {
			if err := s.clientSideBuddyListManager.SetPDMode(ctx, sess.IdentScreenName(), wire.FeedbagPDModePermitAll); err != nil {
				return err
			}
			return s.maybeBroadcastVisibility(ctx, sess, nil)
		}
	}

	if err := s.clientSideBuddyListManager.SetPDMode(ctx, sess.IdentScreenName(), wire.FeedbagPDModeDenySome); err != nil {
		return err
	}

	for _, user := range body.Users {
		sn := state.NewIdentScreenName(user.ScreenName)
		if err := s.clientSideBuddyListManager.DenyBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
	}

	// don't filter users so that users permitted as a result of this
	// visibility change get properly notified
	return s.maybeBroadcastVisibility(ctx, sess, nil)
}

// AddPermListEntries adds users to your permit list and sets your visibility
// mode to "permit some". If your screen name is passed as a single element in
// the input payload, your visibility mode is set to "deny all" instead. Your
// buddy list and your relations' buddy lists are updated to reflect the
// current mode.
func (s PermitDenyService) AddPermListEntries(
	ctx context.Context,
	sess *state.Session,
	body wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries,
) error {
	if len(body.Users) == 1 {
		sn := state.NewIdentScreenName(body.Users[0].ScreenName)
		if sn.String() == sess.IdentScreenName().String() {
			if err := s.clientSideBuddyListManager.SetPDMode(ctx, sess.IdentScreenName(), wire.FeedbagPDModeDenyAll); err != nil {
				return err
			}
			return s.maybeBroadcastVisibility(ctx, sess, nil)
		}
	}

	if err := s.clientSideBuddyListManager.SetPDMode(ctx, sess.IdentScreenName(), wire.FeedbagPDModePermitSome); err != nil {
		return err
	}

	for _, user := range body.Users {
		sn := state.NewIdentScreenName(user.ScreenName)
		if err := s.clientSideBuddyListManager.PermitBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
	}

	// don't filter users so that users blocked as a result of this visibility
	// change get properly notified
	return s.maybeBroadcastVisibility(ctx, sess, nil)
}

// DelDenyListEntries removes users from your deny list. Your buddy list and
// your relations' buddy lists are updated to reflect the list update.
func (s PermitDenyService) DelDenyListEntries(
	ctx context.Context,
	sess *state.Session,
	body wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries,
) error {
	if len(body.Users) == 0 {
		return nil
	}

	for _, user := range body.Users {
		sn := state.NewIdentScreenName(user.ScreenName)
		if err := s.clientSideBuddyListManager.RemoveDenyBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
	}

	return s.maybeBroadcastVisibility(ctx, sess, body.Users)
}

// DelPermListEntries removes users from your permit list. Your buddy list and
// your relations' buddy lists are updated to reflect the list update.
func (s PermitDenyService) DelPermListEntries(
	ctx context.Context,
	sess *state.Session,
	body wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries,
) error {
	if len(body.Users) == 0 {
		return nil
	}

	for _, user := range body.Users {
		sn := state.NewIdentScreenName(user.ScreenName)
		if err := s.clientSideBuddyListManager.RemovePermitBuddy(ctx, sess.IdentScreenName(), sn); err != nil {
			return err
		}
	}

	return s.maybeBroadcastVisibility(ctx, sess, body.Users)
}

// maybeBroadcastVisibility broadcasts visibility changes to a list users only
// if the client has finished signing in, which prevents duplicate arrival
// notifications, which are ultimately sent at the end of the sign on flow.
func (s PermitDenyService) maybeBroadcastVisibility(ctx context.Context, sess *state.Session, body []struct {
	ScreenName string `oscar:"len_prefix=uint8"`
}) error {
	if !sess.SignonComplete() {
		return nil
	}
	var filter []state.IdentScreenName
	if len(body) > 0 {
		filter = make([]state.IdentScreenName, 0, len(body))
		for _, user := range body {
			filter = append(filter, state.NewIdentScreenName(user.ScreenName))
		}
	}
	return s.buddyBroadcaster.BroadcastVisibility(ctx, sess, filter, true)
}

// RightsQuery returns settings for the PermitDeny food group. It returns SNAC
// wire.PermitDenyRightsReply. The values in the return SNAC were arbitrarily
// chosen.
func (s PermitDenyService) RightsQuery(_ context.Context, frame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.PermitDeny,
			SubGroup:  wire.PermitDenyRightsReply,
			RequestID: frame.RequestID,
		},
		Body: wire.SNAC_0x09_0x03_PermitDenyRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.PermitDenyTLVMaxDenies, uint16(100)),
					wire.NewTLVBE(wire.PermitDenyTLVMaxPermits, uint16(100)),
					wire.NewTLVBE(wire.PermitDenyTLVMaxTempPermits, uint16(100)),
				},
			},
		},
	}
}
