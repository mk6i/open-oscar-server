package foodgroup

import (
	"context"
	"errors"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewUserLookupService returns a new instance of UserLookupService.
func NewUserLookupService(profileManager ProfileManager) UserLookupService {
	return UserLookupService{
		profileManager: profileManager,
	}
}

// UserLookupService implements the UserLookup food group.
type UserLookupService struct {
	profileManager ProfileManager
}

// FindByEmail searches for a user by email address.
func (s UserLookupService) FindByEmail(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0A_0x02_UserLookupFindByEmail) (wire.SNACMessage, error) {
	user, err := s.profileManager.FindByAIMEmail(ctx, string(inBody.Email))

	switch {
	case errors.Is(err, state.ErrNoUser):
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.UserLookup,
				SubGroup:  wire.UserLookupErr,
				RequestID: inFrame.RequestID,
			},
			Body: wire.UserLookupErrNoUserFound,
		}, nil
	case err != nil:
		return wire.SNACMessage{}, err
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.UserLookup,
			SubGroup:  wire.UserLookupFindReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x0A_0x03_UserLookupFindReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.UserLookupTLVEmailAddress, user.DisplayScreenName),
				},
			},
		},
	}, nil
}
