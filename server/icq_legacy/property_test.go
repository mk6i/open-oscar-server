package icq_legacy

import (
	"context"
	"log/slog"
	"strconv"
	"testing"
	"testing/quick"

	"github.com/mk6i/open-oscar-server/state"
)

// TestProperty_UINScreenNameRoundTrip verifies Property 8: UIN↔ScreenName round trip.
// For any valid UIN (1 ≤ UIN ≤ 999999999), converting to state.IdentScreenName
// via strconv.FormatUint(uint64(uin), 10) and back via
// strconv.ParseUint(screenName.String(), 10, 32) produces the original UIN.
//
// **Validates: Requirements 7.1, 7.2**
func TestProperty_UINScreenNameRoundTrip(t *testing.T) {
	f := func(raw uint32) bool {
		// Clamp to valid UIN range [1, 999999999]
		uin := (raw % 999999999) + 1

		// Forward: UIN → IdentScreenName
		screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))

		// Reverse: IdentScreenName → UIN
		parsed, err := strconv.ParseUint(screenName.String(), 10, 32)
		if err != nil {
			return false
		}

		return uint32(parsed) == uin
	}

	if err := quick.Check(f, nil); err != nil {
		t.Errorf("UIN↔ScreenName round trip property failed: %v", err)
	}
}

// TestProperty_ServiceBehavioralEquivalence verifies Property 9: Service behavioral equivalence.
// For any valid AuthRequest (UIN 1-999999999, non-empty password), the service
// returns a consistent AuthResult. Specifically, for a user that doesn't exist,
// it always returns {Success: false, ErrorCode: 0x0002}.
//
// **Validates: Requirements 8.1, 8.2**
func TestProperty_ServiceBehavioralEquivalence(t *testing.T) {
	f := func(raw uint32, passByte byte) bool {
		// Clamp to valid UIN range [1, 999999999]
		uin := (raw % 999999999) + 1

		// Generate a non-empty password from the random byte
		password := string([]byte{'a' + passByte%26})

		// Create a service with a mock UserManager that always returns ErrNoUser
		userManager := newMockUserManager(t)
		screenName := state.NewIdentScreenName(strconv.FormatUint(uint64(uin), 10))
		userManager.EXPECT().
			User(matchContext(), screenName).
			Return(nil, state.ErrNoUser)

		svc := NewICQLegacyService(
			userManager,
			newMockAccountManager(t),
			newMockSessionRetriever(t),
			newMockMessageRelayer(t),
			newMockBuddyBroadcaster(t),
			newMockOfflineMessageManager(t),
			newMockICQUserFinder(t),
			newMockICQUserUpdater(t),
			newMockFeedbagManager(t),
			newMockRelationshipFetcher(t),
			newMockBuddyListRegistry(t),
			newMockClientSideBuddyListManager(t),
			slog.Default(),
		)

		result, err := svc.AuthenticateUser(context.Background(), AuthRequest{
			UIN:      uin,
			Password: password,
		})

		if err != nil {
			return false
		}

		// For a non-existent user, the service must always return
		// Success=false with ErrorCode=0x0002 (user not found)
		return !result.Success && result.ErrorCode == 0x0002
	}

	if err := quick.Check(f, nil); err != nil {
		t.Errorf("Service behavioral equivalence property failed: %v", err)
	}
}
