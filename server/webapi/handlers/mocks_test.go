package handlers

import (
	"context"
	"log/slog"

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

// MockBuddyIconRetriever is a mock implementation of BuddyIconRetriever
type MockBuddyIconRetriever struct {
	mock.Mock
}

func (m *MockBuddyIconRetriever) BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error) {
	args := m.Called(ctx, screenName)
	id, _ := args.Get(0).(*wire.BARTID)
	return id, args.Error(1)
}

// MockBARTService is a mock implementation of BARTService
type MockBARTService struct {
	mock.Mock
}

func (m *MockBARTService) RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error) {
	args := m.Called(ctx, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

// newTestIconSource returns a BuddyIconSource whose users have no buddy icon,
// for tests that are not exercising icons.
func newTestIconSource() BuddyIconSource {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	return BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   &MockBARTService{},
		Logger:        slog.Default(),
	}
}
