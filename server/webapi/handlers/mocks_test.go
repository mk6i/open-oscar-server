package handlers

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// MockLocateService is a mock implementation of LocateService
type MockLocateService struct {
	mock.Mock
}

func (m *MockLocateService) SetInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x02_0x04_LocateSetInfo) error {
	args := m.Called(ctx, instance, inBody)
	return args.Error(0)
}

func (m *MockLocateService) UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}
