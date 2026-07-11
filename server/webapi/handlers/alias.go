package handlers

import (
	"context"
	"fmt"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// FeedbagAliases collects the aliases the feedbag owner has assigned to their
// buddies, keyed by normalized screen name. Buddies without an alias are absent.
func FeedbagAliases(items []wire.FeedbagItem) map[string]string {
	aliases := make(map[string]string)
	for _, item := range items {
		if item.ClassID != wire.FeedbagClassIdBuddy || item.Name == "" {
			continue
		}
		alias, ok := item.String(wire.FeedbagAttributesAlias)
		if !ok || alias == "" {
			continue
		}
		aliases[state.NewIdentScreenName(item.Name).String()] = alias
	}
	return aliases
}

// LookupBuddyAliases returns the aliases the session owner has assigned to their
// buddies, keyed by normalized screen name.
//
// Aliases are private to the viewer and live only in their feedbag, so they cannot
// be derived from a locate reply the way display names are.
func LookupBuddyAliases(ctx context.Context, feedbagService FeedbagService, instance *state.SessionInstance) (map[string]string, error) {
	frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
	snac, err := feedbagService.Query(ctx, instance, frame)
	if err != nil {
		return nil, err
	}
	reply, ok := snac.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return nil, fmt.Errorf("unexpected feedbag reply type")
	}
	return FeedbagAliases(reply.Items), nil
}
