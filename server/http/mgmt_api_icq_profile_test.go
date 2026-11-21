package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
)

// icqProfileStore is an in-memory ICQProfileManager holding one ICQ user.
type icqProfileStore struct {
	user  *state.User
	basic *state.ICQBasicInfo
}

func (s *icqProfileStore) User(_ context.Context, sn state.IdentScreenName) (*state.User, error) {
	if s.user.IdentScreenName != sn {
		return nil, nil
	}
	return s.user, nil
}

func (s *icqProfileStore) SetBasicInfo(_ context.Context, _ state.IdentScreenName, data state.ICQBasicInfo) error {
	s.basic = &data
	return nil
}

func (s *icqProfileStore) SetMoreInfo(context.Context, state.IdentScreenName, state.ICQMoreInfo) error {
	return nil
}

func (s *icqProfileStore) SetWorkInfo(context.Context, state.IdentScreenName, state.ICQWorkInfo) error {
	return nil
}

func (s *icqProfileStore) SetUserNotes(context.Context, state.IdentScreenName, state.ICQUserNotes) error {
	return nil
}

func (s *icqProfileStore) SetInterests(context.Context, state.IdentScreenName, state.ICQInterests) error {
	return nil
}

func (s *icqProfileStore) SetAffiliations(context.Context, state.IdentScreenName, state.ICQAffiliations) error {
	return nil
}

func (s *icqProfileStore) SetPermissions(context.Context, state.IdentScreenName, state.ICQPermissions) error {
	return nil
}

func (s *icqProfileStore) SetICQInfo(context.Context, state.IdentScreenName, state.ICQInfo) error {
	return nil
}

func TestPutICQProfileHandler_NicknameLength(t *testing.T) {
	cases := []struct {
		name     string
		nickname string
	}{
		{name: "cyrillic, 18 characters but 32 bytes", nickname: "<Деффачка в кедах>"},
		{name: "emoji", nickname: "Jimm 😎🔥"},
		{name: "longer than a client UI allows", nickname: strings.Repeat("a", 40)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sn := state.NewIdentScreenName("100003")
			store := &icqProfileStore{user: &state.User{IdentScreenName: sn, DisplayScreenName: "100003", IsICQ: true}}

			body, err := json.Marshal(map[string]any{"basic_info": map[string]any{"nickname": tc.nickname}})
			assert.NoError(t, err)
			r := httptest.NewRequest(http.MethodPut, "/user/100003/icq", strings.NewReader(string(body)))
			r.SetPathValue("screenname", "100003")
			w := httptest.NewRecorder()

			putICQProfileHandler(w, r, store, slog.Default())

			assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
			if assert.NotNil(t, store.basic) {
				assert.Equal(t, tc.nickname, store.basic.Nickname)
			}
		})
	}
}

func TestPutICQProfileHandler_OtherFieldsStillLimited(t *testing.T) {
	sn := state.NewIdentScreenName("100003")
	store := &icqProfileStore{user: &state.User{IdentScreenName: sn, DisplayScreenName: "100003", IsICQ: true}}

	body := `{"basic_info":{"first_name":"` + strings.Repeat("a", 65) + `"}}`
	r := httptest.NewRequest(http.MethodPut, "/user/100003/icq", strings.NewReader(body))
	r.SetPathValue("screenname", "100003")
	w := httptest.NewRecorder()

	putICQProfileHandler(w, r, store, slog.Default())

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "basic_info.first_name")
	assert.Nil(t, store.basic)
}
