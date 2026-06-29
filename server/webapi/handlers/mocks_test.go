package handlers

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
)

// MockSessionRetriever is a mock implementation of SessionRetriever
type MockSessionRetriever struct {
	mock.Mock
}

func (m *MockSessionRetriever) AllSessions() []*state.Session {
	args := m.Called()
	if sessions := args.Get(0); sessions != nil {
		return sessions.([]*state.Session)
	}
	return nil
}

func (m *MockSessionRetriever) RetrieveSession(screenName state.IdentScreenName) *state.Session {
	args := m.Called(screenName)
	if session := args.Get(0); session != nil {
		return session.(*state.Session)
	}
	return nil
}

// MockRelationshipFetcher is a mock implementation of RelationshipFetcher
type MockRelationshipFetcher struct {
	mock.Mock
}

func (m *MockRelationshipFetcher) Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error) {
	args := m.Called(ctx, me, them)
	return args.Get(0).(state.Relationship), args.Error(1)
}
