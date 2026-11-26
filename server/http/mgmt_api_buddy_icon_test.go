package http

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestUserBuddyIconHandler_PUT(t *testing.T) {
	sampleGIF := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x32, 0x00, 0x32, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0x32, 0x00, 0x32, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}
	sum := md5.Sum(sampleGIF)
	hash := sum[:]

	me := state.NewIdentScreenName("100003")
	user := &state.User{DisplayScreenName: "100003", IdentScreenName: me}

	// iconItem reports whether item is the feedbag BART item pointing at the
	// uploaded image.
	iconItem := func(item wire.FeedbagItem) bool {
		info, ok := item.Bytes(wire.FeedbagAttributesBartInfo)
		if !ok || item.ClassID != wire.FeedbagClassIdBart {
			return false
		}
		return item.Name == strconv.Itoa(int(wire.BARTTypesBuddyIcon)) && bytes.Contains(info, hash)
	}

	put := func(body []byte, u UserManager, f FeedbagManager, b BARTAssetManager, s SessionRetriever, m MessageRelayer, bb BuddyBroadcaster) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/user/100003/icon", bytes.NewReader(body))
		request.SetPathValue("screenname", "100003")
		recorder := httptest.NewRecorder()
		putUserBuddyIconHandler(recorder, request, u, f, b, s, m, bb, slog.Default(), func(n int) int { return 7 })
		return recorder
	}

	t.Run("unknown user", func(t *testing.T) {
		userManager := newMockUserManager(t)
		userManager.EXPECT().User(matchContext(), me).Return(nil, nil)

		recorder := put(sampleGIF, userManager, newMockFeedbagManager(t), newMockBARTAssetManager(t), newMockSessionRetriever(t), newMockMessageRelayer(t), newMockBuddyBroadcaster(t))

		assert.Equal(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("rejected bodies", func(t *testing.T) {
		tt := []struct {
			name string
			body []byte
			code int
		}{
			{name: "empty", body: nil, code: http.StatusBadRequest},
			{name: "not an image", body: []byte("hello, world"), code: http.StatusBadRequest},
			{name: "too large", body: append(append([]byte{}, sampleGIF...), make([]byte, buddyIconMaxBytes)...), code: http.StatusRequestEntityTooLarge},
		}
		for _, tc := range tt {
			t.Run(tc.name, func(t *testing.T) {
				userManager := newMockUserManager(t)
				userManager.EXPECT().User(matchContext(), me).Return(user, nil)

				// The stores and the relayer carry no expectations: nothing may be written.
				recorder := put(tc.body, userManager, newMockFeedbagManager(t), newMockBARTAssetManager(t), newMockSessionRetriever(t), newMockMessageRelayer(t), newMockBuddyBroadcaster(t))

				assert.Equal(t, tc.code, recorder.Code)
			})
		}
	})

	t.Run("signed-off user gets the icon stored", func(t *testing.T) {
		userManager := newMockUserManager(t)
		userManager.EXPECT().User(matchContext(), me).Return(user, nil)
		bartAssetManager := newMockBARTAssetManager(t)
		bartAssetManager.EXPECT().InsertBARTItem(matchContext(), hash, sampleGIF, wire.BARTTypesBuddyIcon).Return(nil)
		feedbagManager := newMockFeedbagManager(t)
		feedbagManager.EXPECT().Feedbag(matchContext(), me).Return(nil, nil)
		feedbagManager.EXPECT().
			FeedbagUpsert(matchContext(), me, mock.MatchedBy(func(items []wire.FeedbagItem) bool {
				return len(items) == 1 && iconItem(items[0])
			})).
			Return(nil)
		sessionRetriever := newMockSessionRetriever(t)
		sessionRetriever.EXPECT().RetrieveSession(me).Return(nil)

		recorder := put(sampleGIF, userManager, feedbagManager, bartAssetManager, sessionRetriever, newMockMessageRelayer(t), newMockBuddyBroadcaster(t))

		assert.Equal(t, http.StatusOK, recorder.Code)
		var got BARTAsset
		assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
		assert.Equal(t, BARTAsset{Hash: hex.EncodeToString(hash), Type: wire.BARTTypesBuddyIcon}, got)
	})

	t.Run("signed-on user and their buddies are told", func(t *testing.T) {
		session := state.NewSession()
		session.SetIdentScreenName(me)
		session.SetDisplayScreenName("100003")

		userManager := newMockUserManager(t)
		userManager.EXPECT().User(matchContext(), me).Return(user, nil)
		bartAssetManager := newMockBARTAssetManager(t)
		// The same image uploaded before is not an error.
		bartAssetManager.EXPECT().InsertBARTItem(matchContext(), hash, sampleGIF, wire.BARTTypesBuddyIcon).Return(state.ErrBARTItemExists)
		feedbagManager := newMockFeedbagManager(t)
		feedbagManager.EXPECT().Feedbag(matchContext(), me).Return(nil, nil)
		feedbagManager.EXPECT().FeedbagUpsert(matchContext(), me, mock.Anything).Return(nil)
		sessionRetriever := newMockSessionRetriever(t)
		sessionRetriever.EXPECT().RetrieveSession(me).Return(session)
		messageRelayer := newMockMessageRelayer(t)
		messageRelayer.EXPECT().
			RelayToScreenName(matchContext(), me, mock.MatchedBy(func(msg wire.SNACMessage) bool {
				body, ok := msg.Body.(wire.SNAC_0x13_0x09_FeedbagUpdateItem)
				return ok && msg.Frame.SubGroup == wire.FeedbagInsertItem && len(body.Items) == 1 && iconItem(body.Items[0])
			}))
		messageRelayer.EXPECT().
			RelayToScreenName(matchContext(), me, mock.MatchedBy(func(msg wire.SNACMessage) bool {
				return msg.Frame.FoodGroup == wire.OService && msg.Frame.SubGroup == wire.OServiceUserInfoUpdate
			}))
		buddyBroadcaster := newMockBuddyBroadcaster(t)
		buddyBroadcaster.EXPECT().BroadcastBuddyArrived(matchContext(), me, mock.Anything).Return(nil)

		recorder := put(sampleGIF, userManager, feedbagManager, bartAssetManager, sessionRetriever, messageRelayer, buddyBroadcaster)

		assert.Equal(t, http.StatusOK, recorder.Code)
		icon, hasIcon := session.BuddyIcon()
		assert.True(t, hasIcon)
		assert.Equal(t, hash, icon.Hash)
	})
}
