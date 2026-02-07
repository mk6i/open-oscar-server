package state

import (
	"context"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/wire"
)

type CreateAccountFunc func(ctx context.Context, screenName DisplayScreenName, password string) (User, error)

func NewAccountCreator(
	insertUser func(ctx context.Context, u User) error,
	insertFeedbag func(ctx context.Context, screenName IdentScreenName, items []wire.FeedbagItem) error,
) CreateAccountFunc {

	return func(ctx context.Context, screenName DisplayScreenName, password string) (User, error) {
		if screenName.IsUIN() {
			if err := screenName.ValidateUIN(); err != nil {
				return User{}, err
			}
		} else {
			if err := screenName.ValidateAIMHandle(); err != nil {
				return User{}, err
			}
		}

		user := User{
			AuthKey:           uuid.NewString(),
			DisplayScreenName: screenName,
			IdentScreenName:   screenName.IdentScreenName(),
			IsICQ:             screenName.IsUIN(),
		}
		if err := user.HashPassword(password); err != nil {
			return User{}, err
		}

		if err := insertUser(ctx, user); err != nil {
			return User{}, err
		}

		if err := insertFeedbag(ctx, user.IdentScreenName, []wire.FeedbagItem{}); err != nil {
			return User{}, err
		}

		return user, nil
	}
}
