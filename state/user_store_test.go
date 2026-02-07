package state

import (
	"context"
	"fmt"
	"math"
	"net/mail"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFile string = "aim_test.db"

func TestSQLiteUserStore_FeedbagUpsert(t *testing.T) {
	t.Run("buddy screen name is converted to ident screen name", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		given := []wire.FeedbagItem{
			{
				GroupID:   0,
				ItemID:    1805,
				ClassID:   wire.FeedbagClassIdBuddy,
				Name:      "my Friend Bill",
				TLVLBlock: wire.TLVLBlock{},
			},
			{
				GroupID: 0x0A,
				ItemID:  0,
				ClassID: wire.FeedbagClassIdGroup,
				Name:    "Friends",
			},
		}
		expect := []wire.FeedbagItem{
			{
				GroupID:   0,
				ItemID:    1805,
				ClassID:   wire.FeedbagClassIdBuddy,
				Name:      "myfriendbill",
				TLVLBlock: wire.TLVLBlock{},
			},
			{
				GroupID: 0x0A,
				ItemID:  0,
				ClassID: wire.FeedbagClassIdGroup,
				Name:    "Friends",
			},
		}

		me := NewIdentScreenName("me")
		if err := f.FeedbagUpsert(context.Background(), me, given); err != nil {
			t.Fatalf("failed to upsert: %s", err.Error())
		}

		have, err := f.Feedbag(context.Background(), me)
		assert.NoError(t, err)
		assert.ElementsMatch(t, expect, have)
	})

	t.Run("upsert PD info with mode", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		given := []wire.FeedbagItem{
			{
				GroupID: 0x0A,
				ItemID:  0,
				ClassID: wire.FeedbagClassIdPdinfo,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesPdMode, wire.FeedbagPDModePermitSome),
					},
				},
			},
		}

		me := NewIdentScreenName("me")
		err = f.FeedbagUpsert(context.Background(), me, given)
		assert.NoError(t, err)

		var pdMode uint8
		err = f.db.QueryRow(`SELECT pdMode from feedbag WHERE screenName = ?`, me.String()).Scan(&pdMode)
		assert.NoError(t, err)
		assert.Equal(t, wire.FeedbagPDMode(pdMode), wire.FeedbagPDModePermitSome)
	})

	t.Run("upsert PD info without mode (QIP behavior)", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		given := []wire.FeedbagItem{
			{
				GroupID:   0x0A,
				ItemID:    0,
				ClassID:   wire.FeedbagClassIdPdinfo,
				TLVLBlock: wire.TLVLBlock{},
			},
		}

		me := NewIdentScreenName("me")
		err = f.FeedbagUpsert(context.Background(), me, given)
		assert.NoError(t, err)

		var pdMode uint8
		err = f.db.QueryRow(`SELECT pdMode from feedbag WHERE screenName = ?`, me.String()).Scan(&pdMode)
		assert.NoError(t, err)
		assert.Equal(t, wire.FeedbagPDMode(pdMode), wire.FeedbagPDModePermitAll)
	})
}

func TestFeedbagDelete(t *testing.T) {

	screenName := NewIdentScreenName("sn2day")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	itemsIn := []wire.FeedbagItem{
		{
			GroupID: 0,
			ItemID:  1805,
			ClassID: 3,
			Name:    "spimmer1234",
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(0x01, uint16(1000)),
				},
			},
		},
		{
			GroupID: 0x0A,
			ItemID:  0,
			ClassID: 1,
			Name:    "Friends",
		},
		{
			GroupID: 0x0B,
			ItemID:  100,
			ClassID: 1,
			Name:    "co-workers",
		},
	}

	if err := f.FeedbagUpsert(context.Background(), screenName, itemsIn); err != nil {
		t.Fatalf("failed to upsert: %s", err.Error())
	}

	if err := f.FeedbagDelete(context.Background(), screenName, []wire.FeedbagItem{itemsIn[0]}); err != nil {
		t.Fatalf("failed to delete: %s", err.Error())
	}

	itemsOut, err := f.Feedbag(context.Background(), screenName)
	if err != nil {
		t.Fatalf("failed to retrieve: %s", err.Error())
	}

	expect := itemsIn[1:]

	if !reflect.DeepEqual(expect, itemsOut) {
		t.Fatalf("items did not match:\n in: %v\n out: %v", expect, itemsOut)
	}
}

func TestLastModifiedEmpty(t *testing.T) {

	screenName := NewIdentScreenName("sn2day")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	_, err = f.FeedbagLastModified(context.Background(), screenName)

	if err != nil {
		t.Fatalf("get error from last modified: %s", err.Error())
	}
}

func TestLastModifiedNotEmpty(t *testing.T) {

	screenName := NewIdentScreenName("sn2day")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	itemsIn := []wire.FeedbagItem{
		{
			GroupID: 0x0A,
			ItemID:  0,
			ClassID: 1,
			Name:    "Friends",
		},
	}
	if err := f.FeedbagUpsert(context.Background(), screenName, itemsIn); err != nil {
		t.Fatalf("failed to upsert: %s", err.Error())
	}

	_, err = f.FeedbagLastModified(context.Background(), screenName)

	if err != nil {
		t.Fatalf("get error from last modified: %s", err.Error())
	}
}

func TestProfile(t *testing.T) {

	screenName := NewIdentScreenName("sn2day")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	u := User{
		IdentScreenName: screenName,
	}
	if err := f.InsertUser(context.Background(), u); err != nil {
		t.Fatalf("failed to upsert new user: %s", err.Error())
	}

	profile, err := f.Profile(context.Background(), screenName)
	if err != nil {
		t.Fatalf("failed to retrieve profile: %s", err.Error())
	}

	if !profile.IsZero() {
		t.Fatalf("expected empty profile for %s", screenName)
	}

	newProfile := UserProfile{
		ProfileText: "here is my profile",
		MIMEType:    "text/plain",
		UpdateTime:  time.Now().UTC().Truncate(time.Second),
	}
	if err := f.SetProfile(context.Background(), screenName, newProfile); err != nil {
		t.Fatalf("failed to create new profile: %s", err.Error())
	}

	profile, err = f.Profile(context.Background(), screenName)
	if err != nil {
		t.Fatalf("failed to retrieve profile: %s", err.Error())
	}

	if profile.ProfileText != newProfile.ProfileText {
		t.Fatalf("profiles did not match:\n expected: %v\n actual: %v", newProfile.ProfileText, profile.ProfileText)
	}
	if profile.MIMEType != newProfile.MIMEType {
		t.Fatalf("mime types did not match:\n expected: %v\n actual: %v", newProfile.MIMEType, profile.MIMEType)
	}
	if !profile.UpdateTime.Equal(newProfile.UpdateTime) {
		t.Fatalf("update times did not match:\n expected: %v\n actual: %v", newProfile.UpdateTime, profile.UpdateTime)
	}

	updatedProfile := UserProfile{
		ProfileText: "here is my profile [updated]",
		MIMEType:    "text/html",
		UpdateTime:  time.Now().UTC().Truncate(time.Second),
	}
	if err := f.SetProfile(context.Background(), screenName, updatedProfile); err != nil {
		t.Fatalf("failed to create new profile: %s", err.Error())
	}

	profile, err = f.Profile(context.Background(), screenName)
	if err != nil {
		t.Fatalf("failed to retrieve profile: %s", err.Error())
	}

	if profile.ProfileText != updatedProfile.ProfileText {
		t.Fatalf("updated profiles did not match:\n expected: %v\n actual: %v", updatedProfile.ProfileText, profile.ProfileText)
	}
	if profile.MIMEType != updatedProfile.MIMEType {
		t.Fatalf("updated mime types did not match:\n expected: %v\n actual: %v", updatedProfile.MIMEType, profile.MIMEType)
	}
	if !profile.UpdateTime.Equal(updatedProfile.UpdateTime) {
		t.Fatalf("updated update times did not match:\n expected: %v\n actual: %v", updatedProfile.UpdateTime, profile.UpdateTime)
	}
}

func TestProfileNonExistent(t *testing.T) {

	screenName := NewIdentScreenName("sn2day")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	prof, err := f.Profile(context.Background(), screenName)
	assert.NoError(t, err)
	assert.True(t, prof.IsZero())
	assert.Equal(t, "", prof.MIMEType)
	assert.True(t, prof.UpdateTime.IsZero())
}

func TestProfile_MimeTypeAndUpdateTime(t *testing.T) {
	screenName := NewIdentScreenName("testuser")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	require.NoError(t, err)

	u := User{
		IdentScreenName: screenName,
	}
	require.NoError(t, f.InsertUser(context.Background(), u))

	t.Run("profile with empty mimeType and zero updateTime", func(t *testing.T) {
		profile := UserProfile{
			ProfileText: "test profile",
			MIMEType:    "",
			UpdateTime:  time.Time{},
		}
		require.NoError(t, f.SetProfile(context.Background(), screenName, profile))

		retrieved, err := f.Profile(context.Background(), screenName)
		require.NoError(t, err)
		assert.Equal(t, profile.ProfileText, retrieved.ProfileText)
		assert.Equal(t, "", retrieved.MIMEType)
		assert.True(t, retrieved.UpdateTime.IsZero())
	})

	t.Run("profile with mimeType and updateTime", func(t *testing.T) {
		updateTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		profile := UserProfile{
			ProfileText: "test profile with mime",
			MIMEType:    "text/html",
			UpdateTime:  updateTime,
		}
		require.NoError(t, f.SetProfile(context.Background(), screenName, profile))

		retrieved, err := f.Profile(context.Background(), screenName)
		require.NoError(t, err)
		assert.Equal(t, profile.ProfileText, retrieved.ProfileText)
		assert.Equal(t, "text/html", retrieved.MIMEType)
		assert.True(t, retrieved.UpdateTime.Equal(updateTime), "expected %v, got %v", updateTime, retrieved.UpdateTime)
	})

	t.Run("update profile with different mimeType and updateTime", func(t *testing.T) {
		updateTime := time.Date(2024, 2, 20, 14, 45, 0, 0, time.UTC)
		profile := UserProfile{
			ProfileText: "updated profile",
			MIMEType:    "text/plain",
			UpdateTime:  updateTime,
		}
		require.NoError(t, f.SetProfile(context.Background(), screenName, profile))

		retrieved, err := f.Profile(context.Background(), screenName)
		require.NoError(t, err)
		assert.Equal(t, profile.ProfileText, retrieved.ProfileText)
		assert.Equal(t, "text/plain", retrieved.MIMEType)
		assert.True(t, retrieved.UpdateTime.Equal(updateTime), "expected %v, got %v", updateTime, retrieved.UpdateTime)
	})
}

func TestGetUser(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("testscreenname")

	insertedUser := &User{
		IdentScreenName:   screenName,
		DisplayScreenName: DisplayScreenName("testscreenname"),
		AuthKey:           "theauthkey",
		StrongMD5Pass:     []byte("thepasshash"),
		RegStatus:         3,
		LastWarnUpdate:    time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), // Database default value
	}
	err = f.InsertUser(context.Background(), *insertedUser)
	assert.NoError(t, err)

	actualUser, err := f.User(context.Background(), screenName)
	if err != nil {
		t.Fatalf("failed to get user: %s", err.Error())
	}

	if !reflect.DeepEqual(insertedUser, actualUser) {
		t.Fatalf("users are not equal. expect: %v actual: %v", insertedUser, actualUser)
	}
}

func TestSQLiteUserStore_User_OfflineMsgCount(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("testuser")

	// Insert user first
	err = f.InsertUser(context.Background(), User{
		IdentScreenName:   screenName,
		DisplayScreenName: DisplayScreenName("testuser"),
	})
	assert.NoError(t, err)

	// Set offlineMsgCount using the store method
	err = f.SetOfflineMsgCount(context.Background(), screenName, 5)
	assert.NoError(t, err)

	// Retrieve user and verify OfflineMsgCount is loaded
	user, err := f.User(context.Background(), screenName)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, 5, user.OfflineMsgCount)
}

func TestGetUserNotFound(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	actualUser, err := f.User(context.Background(), NewIdentScreenName("testscreenname"))
	if err != nil {
		t.Fatalf("failed to get user: %s", err.Error())
	}

	if actualUser != nil {
		t.Fatal("expected user to not be found")
	}
}

func TestSQLiteUserStore_Users(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	want := []User{
		{
			IdentScreenName:   NewIdentScreenName("userA"),
			DisplayScreenName: "userA",
		},
		{
			IdentScreenName:   NewIdentScreenName("userB"),
			DisplayScreenName: "userB",
		},
		{
			IdentScreenName:   NewIdentScreenName("userC"),
			DisplayScreenName: "userC",
			IsBot:             true,
		},
		{
			IdentScreenName:   NewIdentScreenName("100003"),
			DisplayScreenName: "100003",
			IsICQ:             true,
		},
	}

	for _, u := range want {
		err := f.InsertUser(context.Background(), u)
		assert.NoError(t, err)
	}

	have, err := f.AllUsers(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, want, have)
}

func TestSQLiteUserStore_InsertUser_UINButNotIsICQ(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	user := User{
		IdentScreenName:   NewIdentScreenName("100003"),
		DisplayScreenName: "100003",
	}

	err = f.InsertUser(context.Background(), user)
	assert.ErrorContains(t, err, "inserting user with UIN and isICQ=false")
}

func TestSQLiteUserStore_DeleteUser_DeleteExistentUser(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	err = f.InsertUser(context.Background(), User{
		IdentScreenName:   NewIdentScreenName("userA"),
		DisplayScreenName: "userA",
	})
	assert.NoError(t, err)
	err = f.InsertUser(context.Background(), User{
		IdentScreenName:   NewIdentScreenName("userB"),
		DisplayScreenName: "userB",
	})
	assert.NoError(t, err)

	err = f.DeleteUser(context.Background(), NewIdentScreenName("userA"))
	assert.NoError(t, err)

	have, err := f.AllUsers(context.Background())
	assert.NoError(t, err)

	want := []User{{
		IdentScreenName:   NewIdentScreenName("userB"),
		DisplayScreenName: "userB",
	}}
	assert.Equal(t, want, have)
}

func TestSQLiteUserStore_DeleteUser_DeleteNonExistentUser(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	err = f.DeleteUser(context.Background(), NewIdentScreenName("userA"))
	assert.ErrorIs(t, ErrNoUser, err)
}

func newFeedbagItem(classID uint16, itemID uint16, name string) wire.FeedbagItem {
	return wire.FeedbagItem{
		ClassID: classID,
		ItemID:  itemID,
		Name:    name,
	}
}

func pdInfoItem(itemID uint16, pdMode wire.FeedbagPDMode) wire.FeedbagItem {
	return wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdPdinfo,
		ItemID:  itemID,
		TLVLBlock: wire.TLVLBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(pdMode)),
			},
		},
	}
}

func TestSQLiteUserStore_SetBuddyIconAndRetrieve(t *testing.T) {
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	item := []byte{'a', 'b', 'c', 'd'}

	t.Run("insert_and_retrieve", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		feedbagStore, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		b, err := feedbagStore.BARTItem(context.Background(), hash)
		assert.NoError(t, err)
		assert.Empty(t, b)

		err = feedbagStore.InsertBARTItem(context.Background(), hash, item, 1)
		assert.NoError(t, err)

		b, err = feedbagStore.BARTItem(context.Background(), hash)
		assert.NoError(t, err)
		assert.Equal(t, item, b)
	})

	t.Run("duplicate_insert_returns_error", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		feedbagStore, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// First insert the item
		err = feedbagStore.InsertBARTItem(context.Background(), hash, item, 1)
		assert.NoError(t, err)

		// Try to insert the same hash again
		err = feedbagStore.InsertBARTItem(context.Background(), hash, item, 1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBARTItemExists)
	})
}

func TestSQLiteUserStore_ListBARTItems(t *testing.T) {
	t.Run("empty_list", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		feedbagStore, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		items, err := feedbagStore.ListBARTItems(context.Background(), 1)
		assert.NoError(t, err)
		assert.Empty(t, items)
	})

	t.Run("list_with_items", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		feedbagStore, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Insert some test items of type 1
		hash1 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		item1 := []byte{'a', 'b', 'c', 'd'}
		err = feedbagStore.InsertBARTItem(context.Background(), hash1, item1, 1)
		assert.NoError(t, err)

		hash2 := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
		item2 := []byte{'e', 'f', 'g', 'h'}
		err = feedbagStore.InsertBARTItem(context.Background(), hash2, item2, 1)
		assert.NoError(t, err)

		// List items of type 1
		items, err := feedbagStore.ListBARTItems(context.Background(), 1)
		assert.NoError(t, err)
		assert.Len(t, items, 2)

		// Check that items are sorted by hash
		assert.Equal(t, "000102030405060708090a0b0c0d0e0f", items[0].Hash)
		assert.Equal(t, uint16(1), items[0].Type)
		assert.Equal(t, "0f0e0d0c0b0a09080706050403020100", items[1].Hash)
		assert.Equal(t, uint16(1), items[1].Type)
	})
}

func TestSQLiteUserStore_SetUserPassword_UserExists(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	feedbagStore, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	u := User{
		IdentScreenName:   NewIdentScreenName("theuser"),
		DisplayScreenName: "theUser",
	}
	err = u.HashPassword("thepassword")
	assert.NoError(t, err)

	err = feedbagStore.InsertUser(context.Background(), u)
	assert.NoError(t, err)

	err = feedbagStore.SetUserPassword(context.Background(), u.IdentScreenName, "theNEWpassword")
	assert.NoError(t, err)

	gotUser, err := feedbagStore.User(context.Background(), u.IdentScreenName)
	assert.NoError(t, err)

	wantUser := User{}
	wantUser.HashPassword("theNEWpassword")

	valid := gotUser.ValidateHash(wantUser.StrongMD5Pass)
	assert.True(t, valid)
}

func TestSQLiteUserStore_SetUserPassword_ErrNoUser(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	feedbagStore, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	err = feedbagStore.SetUserPassword(context.Background(), NewIdentScreenName("some_user"), "thepassword")
	assert.ErrorIs(t, err, ErrNoUser)
}

func TestSQLiteUserStore_ChatRoomByCookie(t *testing.T) {
	tests := []struct {
		name        string
		givenRoom   ChatRoom
		lookupRoom  ChatRoom
		expectedErr error
	}{
		{
			name:        "chat room found",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: nil,
		},
		{
			name:        "chat room found - different name casing",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("MY CHAT ROOM", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: nil,
		},
		{
			name:        "chat room not found",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("your chat room", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: ErrChatRoomNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				assert.NoError(t, os.Remove(testFile))
			}()

			userStore, err := NewSQLiteUserStore(testFile)
			assert.NoError(t, err)

			err = userStore.CreateChatRoom(context.Background(), &tt.givenRoom)
			assert.NoError(t, err)

			gotRoom, err := userStore.ChatRoomByCookie(context.Background(), tt.lookupRoom.Cookie())
			assert.ErrorIs(t, err, tt.expectedErr)
			if tt.expectedErr == nil {
				assert.Equal(t, tt.givenRoom.Cookie(), gotRoom.Cookie())
			}
		})
	}
}

func TestSQLiteUserStore_ChatRoomByName(t *testing.T) {
	tests := []struct {
		name        string
		givenRoom   ChatRoom
		lookupRoom  ChatRoom
		expectedErr error
	}{
		{
			name:        "chat room found",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: nil,
		},
		{
			name:        "chat room found - different name casing",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("MY CHAT ROOM", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: nil,
		},
		{
			name:        "chat room not found",
			givenRoom:   NewChatRoom("my chat room", NewIdentScreenName("creator"), PrivateExchange),
			lookupRoom:  NewChatRoom("your chat room", NewIdentScreenName("creator"), PrivateExchange),
			expectedErr: ErrChatRoomNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				assert.NoError(t, os.Remove(testFile))
			}()

			userStore, err := NewSQLiteUserStore(testFile)
			assert.NoError(t, err)

			err = userStore.CreateChatRoom(context.Background(), &tt.givenRoom)
			assert.NoError(t, err)

			gotRoom, err := userStore.ChatRoomByName(context.Background(), tt.lookupRoom.Exchange(), tt.lookupRoom.Name())
			assert.ErrorIs(t, err, tt.expectedErr)
			if tt.expectedErr == nil {
				assert.Equal(t, tt.givenRoom.Cookie(), gotRoom.Cookie())
			}
		})
	}
}

func TestSQLiteUserStore_AllChatRooms(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	userStore, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	chatRooms := []ChatRoom{
		NewChatRoom("chat room 1", NewIdentScreenName("creator"), PrivateExchange),
		NewChatRoom("chat room 2", NewIdentScreenName("creator"), PrivateExchange),
		NewChatRoom("chat room 3", NewIdentScreenName("creator"), PublicExchange),
	}

	for i := range chatRooms {
		tBefore := (&chatRooms[i]).CreateTime()
		err = userStore.CreateChatRoom(context.Background(), &chatRooms[i])
		assert.NoError(t, err)
		assert.True(t, chatRooms[i].CreateTime().After(tBefore))
	}

	// public exchange
	gotRooms, err := userStore.AllChatRooms(context.Background(), 5)
	assert.NoError(t, err)

	assert.Equal(t, chatRooms[2:], gotRooms)

	// private exchange
	gotRooms, err = userStore.AllChatRooms(context.Background(), 4)
	assert.NoError(t, err)

	assert.Equal(t, chatRooms[0:2], gotRooms)
}

func TestSQLiteUserStore_CreateChatRoom_ErrChatRoomExists(t *testing.T) {

	tt := []struct {
		name         string
		firstInsert  ChatRoom
		secondInsert ChatRoom
		wantErr      error
	}{
		{
			name:         "create two rooms with different cookie/exchange, same name",
			firstInsert:  NewChatRoom("chat room", NewIdentScreenName("creator"), PublicExchange),
			secondInsert: NewChatRoom("chat room", NewIdentScreenName("creator"), PrivateExchange),
			wantErr:      nil,
		},
		{
			name:         "create two rooms with same cookie/exchange/name",
			firstInsert:  NewChatRoom("chat room", NewIdentScreenName("creator"), PublicExchange),
			secondInsert: NewChatRoom("chat room", NewIdentScreenName("creator"), PublicExchange),
			wantErr:      ErrDupChatRoom,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				assert.NoError(t, os.Remove(testFile))
			}()

			userStore, err := NewSQLiteUserStore(testFile)
			assert.NoError(t, err)

			err = userStore.CreateChatRoom(context.Background(), &tc.firstInsert)
			assert.NoError(t, err)

			err = userStore.CreateChatRoom(context.Background(), &tc.secondInsert)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestUpdateDisplayScreenName(t *testing.T) {

	screenNameOriginal := DisplayScreenName("chattingchuck")
	screenNameFormatted := DisplayScreenName("Chatting Chuck")

	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	user := User{
		DisplayScreenName: screenNameOriginal,
		IdentScreenName:   screenNameOriginal.IdentScreenName(),
		RegStatus:         3,
	}
	if err := f.InsertUser(context.Background(), user); err != nil {
		t.Fatalf("failed to upsert new user: %s", err.Error())
	}
	err = f.UpdateDisplayScreenName(context.Background(), screenNameFormatted)
	if err != nil {
		t.Fatalf("failed to update display screen name: %s", err.Error())
	}

	dbUser, err := f.User(context.Background(), screenNameOriginal.IdentScreenName())
	if err != nil {
		t.Fatalf("failed to retrieve screen name: %s", err.Error())
	}

	assert.Equal(t, dbUser.DisplayScreenName, screenNameFormatted)
}

func TestSQLiteUserStore_SetWorkInfo(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the work info to set
	workInfo := ICQWorkInfo{
		Company:        "Test Company",
		Department:     "Test Department",
		OccupationCode: 10,
		Position:       "Test Position",
		Address:        "123 Test St",
		City:           "Test City",
		CountryCode:    1,
		Fax:            "123-456-7890",
		Phone:          "098-765-4321",
		State:          "Test State",
		WebPage:        "http://www.test.com",
		ZIPCode:        "12345",
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetWorkInfo
		err := f.SetWorkInfo(context.Background(), screenName, workInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify the work info was set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, workInfo.Company, updatedUser.ICQWorkInfo.Company)
		assert.Equal(t, workInfo.Department, updatedUser.ICQWorkInfo.Department)
		assert.Equal(t, workInfo.OccupationCode, updatedUser.ICQWorkInfo.OccupationCode)
		assert.Equal(t, workInfo.Position, updatedUser.ICQWorkInfo.Position)
		assert.Equal(t, workInfo.Address, updatedUser.ICQWorkInfo.Address)
		assert.Equal(t, workInfo.City, updatedUser.ICQWorkInfo.City)
		assert.Equal(t, workInfo.CountryCode, updatedUser.ICQWorkInfo.CountryCode)
		assert.Equal(t, workInfo.Fax, updatedUser.ICQWorkInfo.Fax)
		assert.Equal(t, workInfo.Phone, updatedUser.ICQWorkInfo.Phone)
		assert.Equal(t, workInfo.State, updatedUser.ICQWorkInfo.State)
		assert.Equal(t, workInfo.WebPage, updatedUser.ICQWorkInfo.WebPage)
		assert.Equal(t, workInfo.ZIPCode, updatedUser.ICQWorkInfo.ZIPCode)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set work info for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetWorkInfo(context.Background(), nonExistingScreenName, workInfo)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Work Info", func(t *testing.T) {
		// Test updating with empty work info (depending on business rules, this might be allowed or not)
		emptyWorkInfo := ICQWorkInfo{}
		err := f.SetWorkInfo(context.Background(), screenName, emptyWorkInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify that fields are empty or have default values
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQWorkInfo.Company)
		assert.Empty(t, updatedUser.ICQWorkInfo.Department)
		assert.Empty(t, updatedUser.ICQWorkInfo.OccupationCode)
		assert.Empty(t, updatedUser.ICQWorkInfo.Position)
		assert.Empty(t, updatedUser.ICQWorkInfo.Address)
		assert.Empty(t, updatedUser.ICQWorkInfo.City)
		assert.Empty(t, updatedUser.ICQWorkInfo.CountryCode)
		assert.Empty(t, updatedUser.ICQWorkInfo.Fax)
		assert.Empty(t, updatedUser.ICQWorkInfo.Phone)
		assert.Empty(t, updatedUser.ICQWorkInfo.State)
		assert.Empty(t, updatedUser.ICQWorkInfo.WebPage)
		assert.Empty(t, updatedUser.ICQWorkInfo.ZIPCode)
	})
}

func TestSQLiteUserStore_SetMoreInfo(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create a test user
	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the more info data to set
	moreInfo := ICQMoreInfo{
		BirthDay:     15,
		BirthMonth:   8,
		BirthYear:    1990,
		Gender:       1,
		HomePageAddr: "http://example.com",
		Lang1:        1,
		Lang2:        2,
		Lang3:        3,
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetMoreInfo
		err := f.SetMoreInfo(context.Background(), screenName, moreInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify the more info was set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, moreInfo.BirthDay, updatedUser.ICQMoreInfo.BirthDay)
		assert.Equal(t, moreInfo.BirthMonth, updatedUser.ICQMoreInfo.BirthMonth)
		assert.Equal(t, moreInfo.BirthYear, updatedUser.ICQMoreInfo.BirthYear)
		assert.Equal(t, moreInfo.Gender, updatedUser.ICQMoreInfo.Gender)
		assert.Equal(t, moreInfo.HomePageAddr, updatedUser.ICQMoreInfo.HomePageAddr)
		assert.Equal(t, moreInfo.Lang1, updatedUser.ICQMoreInfo.Lang1)
		assert.Equal(t, moreInfo.Lang2, updatedUser.ICQMoreInfo.Lang2)
		assert.Equal(t, moreInfo.Lang3, updatedUser.ICQMoreInfo.Lang3)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set more info for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetMoreInfo(context.Background(), nonExistingScreenName, moreInfo)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty More Info", func(t *testing.T) {
		// Test updating with empty more info
		emptyMoreInfo := ICQMoreInfo{}
		err := f.SetMoreInfo(context.Background(), screenName, emptyMoreInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify that fields are empty or have default values
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQMoreInfo.BirthDay)
		assert.Empty(t, updatedUser.ICQMoreInfo.BirthMonth)
		assert.Empty(t, updatedUser.ICQMoreInfo.BirthYear)
		assert.Empty(t, updatedUser.ICQMoreInfo.Gender)
		assert.Empty(t, updatedUser.ICQMoreInfo.HomePageAddr)
		assert.Empty(t, updatedUser.ICQMoreInfo.Lang1)
		assert.Empty(t, updatedUser.ICQMoreInfo.Lang2)
		assert.Empty(t, updatedUser.ICQMoreInfo.Lang3)
	})
}

func TestSQLiteUserStore_SetUserNotes(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create a test user
	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the user notes to set
	userNotes := ICQUserNotes{
		Notes: "This is a test note.",
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetUserNotes
		err := f.SetUserNotes(context.Background(), screenName, userNotes)
		assert.NoError(t, err)

		// Retrieve the user and verify the notes were set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, userNotes.Notes, updatedUser.ICQNotes.Notes)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set notes for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetUserNotes(context.Background(), nonExistingScreenName, userNotes)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Notes", func(t *testing.T) {
		// Test updating with empty notes
		emptyNotes := ICQUserNotes{Notes: ""}
		err := f.SetUserNotes(context.Background(), screenName, emptyNotes)
		assert.NoError(t, err)

		// Retrieve the user and verify that notes are empty
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQNotes.Notes)
	})
}

func TestSQLiteUserStore_SetInterests(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create a test user
	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the interests data to set
	interests := ICQInterests{
		Code1:    1,
		Keyword1: "Coding",
		Code2:    2,
		Keyword2: "Music",
		Code3:    3,
		Keyword3: "Gaming",
		Code4:    4,
		Keyword4: "Travel",
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetInterests
		err := f.SetInterests(context.Background(), screenName, interests)
		assert.NoError(t, err)

		// Retrieve the user and verify the interests were set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, interests.Code1, updatedUser.ICQInterests.Code1)
		assert.Equal(t, interests.Keyword1, updatedUser.ICQInterests.Keyword1)
		assert.Equal(t, interests.Code2, updatedUser.ICQInterests.Code2)
		assert.Equal(t, interests.Keyword2, updatedUser.ICQInterests.Keyword2)
		assert.Equal(t, interests.Code3, updatedUser.ICQInterests.Code3)
		assert.Equal(t, interests.Keyword3, updatedUser.ICQInterests.Keyword3)
		assert.Equal(t, interests.Code4, updatedUser.ICQInterests.Code4)
		assert.Equal(t, interests.Keyword4, updatedUser.ICQInterests.Keyword4)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set interests for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetInterests(context.Background(), nonExistingScreenName, interests)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Interests", func(t *testing.T) {
		// Test updating with empty interests
		emptyInterests := ICQInterests{}
		err := f.SetInterests(context.Background(), screenName, emptyInterests)
		assert.NoError(t, err)

		// Retrieve the user and verify that interests fields are empty or have default values
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQInterests.Code1)
		assert.Empty(t, updatedUser.ICQInterests.Keyword1)
		assert.Empty(t, updatedUser.ICQInterests.Code2)
		assert.Empty(t, updatedUser.ICQInterests.Keyword2)
		assert.Empty(t, updatedUser.ICQInterests.Code3)
		assert.Empty(t, updatedUser.ICQInterests.Keyword3)
		assert.Empty(t, updatedUser.ICQInterests.Code4)
		assert.Empty(t, updatedUser.ICQInterests.Keyword4)
	})
}

func TestSQLiteUserStore_SetAffiliations(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create a test user
	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the affiliations data to set
	affiliations := ICQAffiliations{
		CurrentCode1:    1,
		CurrentKeyword1: "Sports",
		CurrentCode2:    2,
		CurrentKeyword2: "Science",
		CurrentCode3:    3,
		CurrentKeyword3: "Arts",
		PastCode1:       4,
		PastKeyword1:    "Literature",
		PastCode2:       5,
		PastKeyword2:    "Music",
		PastCode3:       6,
		PastKeyword3:    "Technology",
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetAffiliations
		err := f.SetAffiliations(context.Background(), screenName, affiliations)
		assert.NoError(t, err)

		// Retrieve the user and verify the affiliations were set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, affiliations.CurrentCode1, updatedUser.ICQAffiliations.CurrentCode1)
		assert.Equal(t, affiliations.CurrentKeyword1, updatedUser.ICQAffiliations.CurrentKeyword1)
		assert.Equal(t, affiliations.CurrentCode2, updatedUser.ICQAffiliations.CurrentCode2)
		assert.Equal(t, affiliations.CurrentKeyword2, updatedUser.ICQAffiliations.CurrentKeyword2)
		assert.Equal(t, affiliations.CurrentCode3, updatedUser.ICQAffiliations.CurrentCode3)
		assert.Equal(t, affiliations.CurrentKeyword3, updatedUser.ICQAffiliations.CurrentKeyword3)
		assert.Equal(t, affiliations.PastCode1, updatedUser.ICQAffiliations.PastCode1)
		assert.Equal(t, affiliations.PastKeyword1, updatedUser.ICQAffiliations.PastKeyword1)
		assert.Equal(t, affiliations.PastCode2, updatedUser.ICQAffiliations.PastCode2)
		assert.Equal(t, affiliations.PastKeyword2, updatedUser.ICQAffiliations.PastKeyword2)
		assert.Equal(t, affiliations.PastCode3, updatedUser.ICQAffiliations.PastCode3)
		assert.Equal(t, affiliations.PastKeyword3, updatedUser.ICQAffiliations.PastKeyword3)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set affiliations for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetAffiliations(context.Background(), nonExistingScreenName, affiliations)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Affiliations", func(t *testing.T) {
		// Test updating with empty affiliations
		emptyAffiliations := ICQAffiliations{}
		err := f.SetAffiliations(context.Background(), screenName, emptyAffiliations)
		assert.NoError(t, err)

		// Retrieve the user and verify that affiliations fields are empty or have default values
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentCode1)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentKeyword1)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentCode2)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentKeyword2)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentCode3)
		assert.Empty(t, updatedUser.ICQAffiliations.CurrentKeyword3)
		assert.Empty(t, updatedUser.ICQAffiliations.PastCode1)
		assert.Empty(t, updatedUser.ICQAffiliations.PastKeyword1)
		assert.Empty(t, updatedUser.ICQAffiliations.PastCode2)
		assert.Empty(t, updatedUser.ICQAffiliations.PastKeyword2)
		assert.Empty(t, updatedUser.ICQAffiliations.PastCode3)
		assert.Empty(t, updatedUser.ICQAffiliations.PastKeyword3)
	})
}

func TestSQLiteUserStore_SetBasicInfo(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create a test user
	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	// Define the basic info data to set
	basicInfo := ICQBasicInfo{
		CellPhone:    "123-456-7890",
		CountryCode:  1,
		EmailAddress: "test@example.com",
		FirstName:    "John",
		GMTOffset:    5,
		Address:      "123 Main St",
		City:         "Test City",
		Fax:          "098-765-4321",
		Phone:        "111-222-3333",
		State:        "Test State",
		LastName:     "Doe",
		Nickname:     "Johnny",
		PublishEmail: true,
		ZIPCode:      "12345",
	}

	t.Run("Successful Update", func(t *testing.T) {
		// Call SetBasicInfo
		err := f.SetBasicInfo(context.Background(), screenName, basicInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify the basic info was set correctly
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, basicInfo.CellPhone, updatedUser.ICQBasicInfo.CellPhone)
		assert.Equal(t, basicInfo.CountryCode, updatedUser.ICQBasicInfo.CountryCode)
		assert.Equal(t, basicInfo.EmailAddress, updatedUser.ICQBasicInfo.EmailAddress)
		assert.Equal(t, basicInfo.FirstName, updatedUser.ICQBasicInfo.FirstName)
		assert.Equal(t, basicInfo.GMTOffset, updatedUser.ICQBasicInfo.GMTOffset)
		assert.Equal(t, basicInfo.Address, updatedUser.ICQBasicInfo.Address)
		assert.Equal(t, basicInfo.City, updatedUser.ICQBasicInfo.City)
		assert.Equal(t, basicInfo.Fax, updatedUser.ICQBasicInfo.Fax)
		assert.Equal(t, basicInfo.Phone, updatedUser.ICQBasicInfo.Phone)
		assert.Equal(t, basicInfo.State, updatedUser.ICQBasicInfo.State)
		assert.Equal(t, basicInfo.LastName, updatedUser.ICQBasicInfo.LastName)
		assert.Equal(t, basicInfo.Nickname, updatedUser.ICQBasicInfo.Nickname)
		assert.Equal(t, basicInfo.PublishEmail, updatedUser.ICQBasicInfo.PublishEmail)
		assert.Equal(t, basicInfo.ZIPCode, updatedUser.ICQBasicInfo.ZIPCode)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		// Try to set basic info for a non-existing user
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetBasicInfo(context.Background(), nonExistingScreenName, basicInfo)

		// This should return ErrNoUser, as the user does not exist
		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Basic Info", func(t *testing.T) {
		// Test updating with empty basic info
		emptyBasicInfo := ICQBasicInfo{}
		err := f.SetBasicInfo(context.Background(), screenName, emptyBasicInfo)
		assert.NoError(t, err)

		// Retrieve the user and verify that basic info fields are empty or have default values
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.ICQBasicInfo.CellPhone)
		assert.Empty(t, updatedUser.ICQBasicInfo.CountryCode)
		assert.Empty(t, updatedUser.ICQBasicInfo.EmailAddress)
		assert.Empty(t, updatedUser.ICQBasicInfo.FirstName)
		assert.Empty(t, updatedUser.ICQBasicInfo.GMTOffset)
		assert.Empty(t, updatedUser.ICQBasicInfo.Address)
		assert.Empty(t, updatedUser.ICQBasicInfo.City)
		assert.Empty(t, updatedUser.ICQBasicInfo.Fax)
		assert.Empty(t, updatedUser.ICQBasicInfo.Phone)
		assert.Empty(t, updatedUser.ICQBasicInfo.State)
		assert.Empty(t, updatedUser.ICQBasicInfo.LastName)
		assert.Empty(t, updatedUser.ICQBasicInfo.Nickname)
		assert.Empty(t, updatedUser.ICQBasicInfo.PublishEmail)
		assert.Empty(t, updatedUser.ICQBasicInfo.ZIPCode)
	})
}

func TestSQLiteUserStore_FindByICQInterests(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users with different interests
	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	interests1 := ICQInterests{
		Code1:    1,
		Keyword1: "Coding",
		Code2:    2,
		Keyword2: "Music",
	}
	err = f.SetInterests(context.Background(), user1.IdentScreenName, interests1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	interests2 := ICQInterests{
		Code1:    1,
		Keyword1: "Coding",
		Code3:    3,
		Keyword3: "Gaming",
	}
	err = f.SetInterests(context.Background(), user2.IdentScreenName, interests2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	interests3 := ICQInterests{
		Code2:    2,
		Keyword2: "Music",
		Code4:    4,
		Keyword4: "Travel",
	}
	err = f.SetInterests(context.Background(), user3.IdentScreenName, interests3)
	assert.NoError(t, err)

	// Helper function to check if a user with a specific IdentScreenName exists in the results
	containsUserWithScreenName := func(users []User, screenName IdentScreenName) bool {
		for _, user := range users {
			if user.IdentScreenName == screenName {
				return true
			}
		}
		return false
	}

	t.Run("Find Users by Single Keyword", func(t *testing.T) {
		// Search for users interested in "Music"
		users, err := f.FindByICQInterests(context.Background(), 2, []string{"Music"})
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("Find Users by Multiple Keywords", func(t *testing.T) {
		// Search for users interested in "Coding" or "Gaming"
		users, err := f.FindByICQInterests(context.Background(), 1, []string{"Coding", "Gaming"})
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))
	})

	t.Run("Find Users by Multiple Codes and Keywords", func(t *testing.T) {
		// Search for users interested in "Coding"
		users, err := f.FindByICQInterests(context.Background(), 1, []string{"Coding"})
		assert.NoError(t, err)
		assert.Len(t, users, 2)
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))

		// Search for users interested in "Travel"
		users, err = f.FindByICQInterests(context.Background(), 4, []string{"Travel"})
		assert.NoError(t, err)
		assert.Len(t, users, 1)
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("No Users Found", func(t *testing.T) {
		// Search for users interested in a keyword that no user has
		users, err := f.FindByICQInterests(context.Background(), 1, []string{"Status"})
		assert.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestSQLiteUserStore_FindByICQKeyword(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users with different interests
	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	interests1 := ICQInterests{
		Keyword1: "Coding",
		Keyword2: "Music",
	}
	err = f.SetInterests(context.Background(), user1.IdentScreenName, interests1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	interests2 := ICQInterests{
		Keyword1: "Coding",
		Keyword3: "Gaming",
	}
	err = f.SetInterests(context.Background(), user2.IdentScreenName, interests2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	interests3 := ICQInterests{
		Keyword3: "Music",
		Keyword4: "Travel",
	}
	err = f.SetInterests(context.Background(), user3.IdentScreenName, interests3)
	assert.NoError(t, err)

	// Helper function to check if a user with a specific IdentScreenName exists in the results
	containsUserWithScreenName := func(users []User, screenName IdentScreenName) bool {
		for _, user := range users {
			if user.IdentScreenName == screenName {
				return true
			}
		}
		return false
	}

	t.Run("Find Users by Keyword", func(t *testing.T) {
		// Search for users interested in "Music"
		users, err := f.FindByICQKeyword(context.Background(), "Music")
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("No Users Found", func(t *testing.T) {
		// Search for users interested in a keyword that no user has
		users, err := f.FindByICQKeyword(context.Background(), "Knitting")
		assert.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestSQLiteUserStore_FindByICQName(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users with different details using SetBasicInfo
	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	basicInfo1 := ICQBasicInfo{
		FirstName: "John",
		LastName:  "Doe",
		Nickname:  "Johnny",
	}
	err = f.SetBasicInfo(context.Background(), user1.IdentScreenName, basicInfo1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	basicInfo2 := ICQBasicInfo{
		FirstName: "Jane",
		LastName:  "Smith",
		Nickname:  "Janey",
	}
	err = f.SetBasicInfo(context.Background(), user2.IdentScreenName, basicInfo2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	basicInfo3 := ICQBasicInfo{
		FirstName: "John",
		LastName:  "Smith",
		Nickname:  "JohnnyS",
	}
	err = f.SetBasicInfo(context.Background(), user3.IdentScreenName, basicInfo3)
	assert.NoError(t, err)

	// Helper function to check if a user with a specific IdentScreenName exists in the results
	containsUserWithScreenName := func(users []User, screenName IdentScreenName) bool {
		for _, user := range users {
			if user.IdentScreenName == screenName {
				return true
			}
		}
		return false
	}

	t.Run("Find Users by First Cookie", func(t *testing.T) {
		// Search for users with the first name "John"
		users, err := f.FindByICQName(context.Background(), "John", "", "")
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("Find Users by Last Cookie", func(t *testing.T) {
		// Search for users with the last name "Smith"
		users, err := f.FindByICQName(context.Background(), "", "Smith", "")
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("Find Users by Nickname", func(t *testing.T) {
		// Search for users with the nickname "Johnny"
		users, err := f.FindByICQName(context.Background(), "", "", "Johnny")
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		// Check that the correct user is returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
	})

	t.Run("Find Users by Multiple Fields", func(t *testing.T) {
		// Search for users with the first name "Jane" and last name "Smith"
		users, err := f.FindByICQName(context.Background(), "Jane", "Smith", "")
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		// Check that the correct user is returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))
	})

	t.Run("No Users Found", func(t *testing.T) {
		// Search for users with a first name that no user has
		users, err := f.FindByICQName(context.Background(), "NonExistent", "", "")
		assert.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestSQLiteUserStore_FindByDirectoryInfo(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users with different directory info
	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	directoryInfo1 := AIMNameAndAddr{
		FirstName: "John",
		LastName:  "Doe",
		NickName:  "Johnny",
		City:      "New York",
	}
	err = f.SetDirectoryInfo(context.Background(), user1.IdentScreenName, directoryInfo1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	directoryInfo2 := AIMNameAndAddr{
		FirstName: "Jane",
		LastName:  "Smith",
		NickName:  "Janey",
		Country:   "USA",
	}
	err = f.SetDirectoryInfo(context.Background(), user2.IdentScreenName, directoryInfo2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	directoryInfo3 := AIMNameAndAddr{
		FirstName: "John",
		LastName:  "Smith",
		NickName:  "JohnnyS",
		State:     "California",
	}
	err = f.SetDirectoryInfo(context.Background(), user3.IdentScreenName, directoryInfo3)
	assert.NoError(t, err)

	// Helper function to check if a user with a specific IdentScreenName exists in the results
	containsUserWithScreenName := func(users []User, screenName IdentScreenName) bool {
		for _, user := range users {
			if user.IdentScreenName == screenName {
				return true
			}
		}
		return false
	}

	t.Run("Find Users by First Cookie", func(t *testing.T) {
		// Search for users with the first name "John"
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{FirstName: "John"})
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("Find Users by Last Cookie", func(t *testing.T) {
		// Search for users with the last name "Smith"
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{LastName: "Smith"})
		assert.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that the correct users are returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))
		assert.True(t, containsUserWithScreenName(users, user3.IdentScreenName))
	})

	t.Run("Find Users by Nickname", func(t *testing.T) {
		// Search for users with the nickname "Johnny"
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{NickName: "Johnny"})
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		// Check that the correct user is returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
	})

	t.Run("Find Users by City", func(t *testing.T) {
		// Search for users with the city "New York"
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{City: "New York"})
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		// Check that the correct user is returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user1.IdentScreenName))
	})

	t.Run("Find Users by Multiple Fields", func(t *testing.T) {
		// Search for users with the first name "Jane" and country "USA"
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{FirstName: "Jane", Country: "USA"})
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		// Check that the correct user is returned by IdentScreenName
		assert.True(t, containsUserWithScreenName(users, user2.IdentScreenName))
	})

	t.Run("No Users Found", func(t *testing.T) {
		// Search for users with a first name that no user has
		users, err := f.FindByAIMNameAndAddr(context.Background(), AIMNameAndAddr{FirstName: "NonExistent"})
		assert.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestSQLiteUserStore_FindByICQEmail(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users with different email addresses using SetBasicInfo
	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	basicInfo1 := ICQBasicInfo{
		EmailAddress: "user1@example.com",
	}
	err = f.SetBasicInfo(context.Background(), user1.IdentScreenName, basicInfo1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	basicInfo2 := ICQBasicInfo{
		EmailAddress: "user2@example.com",
	}
	err = f.SetBasicInfo(context.Background(), user2.IdentScreenName, basicInfo2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	basicInfo3 := ICQBasicInfo{
		EmailAddress: "user3@example.com",
	}
	err = f.SetBasicInfo(context.Background(), user3.IdentScreenName, basicInfo3)
	assert.NoError(t, err)

	t.Run("Find User by Email", func(t *testing.T) {
		// Search for user with email "user1@example.com"
		user, err := f.FindByICQEmail(context.Background(), "user1@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user1.IdentScreenName, user.IdentScreenName)

		// Search for user with email "user2@example.com"
		user, err = f.FindByICQEmail(context.Background(), "user2@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user2.IdentScreenName, user.IdentScreenName)

		// Search for user with email "user3@example.com"
		user, err = f.FindByICQEmail(context.Background(), "user3@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user3.IdentScreenName, user.IdentScreenName)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Search for an email that doesn't exist
		_, err := f.FindByICQEmail(context.Background(), "nonexistent@example.com")
		assert.ErrorIs(t, err, ErrNoUser)
	})
}

func TestSQLiteUserStore_FindByAIMEmail(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	user1 := User{
		IdentScreenName: NewIdentScreenName("user1"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)
	err = f.UpdateEmailAddress(context.Background(), user1.IdentScreenName, &mail.Address{Address: "user1@example.com"})
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("user2"),
		EmailAddress:    "user2@example.com",
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)
	err = f.UpdateEmailAddress(context.Background(), user2.IdentScreenName, &mail.Address{Address: "user2@example.com"})
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("user3"),
		EmailAddress:    "user3@example.com",
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)
	err = f.UpdateEmailAddress(context.Background(), user3.IdentScreenName, &mail.Address{Address: "user3@example.com"})
	assert.NoError(t, err)

	t.Run("Find User by Email", func(t *testing.T) {
		// Search for user with email "user1@example.com"
		user, err := f.FindByAIMEmail(context.Background(), "user1@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user1.IdentScreenName, user.IdentScreenName)

		// Search for user with email "user2@example.com"
		user, err = f.FindByAIMEmail(context.Background(), "user2@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user2.IdentScreenName, user.IdentScreenName)

		// Search for user with email "user3@example.com"
		user, err = f.FindByAIMEmail(context.Background(), "user3@example.com")
		assert.NoError(t, err)
		assert.Equal(t, user3.IdentScreenName, user.IdentScreenName)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Search for an email that doesn't exist
		_, err := f.FindByAIMEmail(context.Background(), "nonexistent@example.com")
		assert.ErrorIs(t, err, ErrNoUser)
	})
}

func TestSQLiteUserStore_FindByUIN(t *testing.T) {
	// Cleanup after test
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	// Initialize the SQLiteUserStore with a test database file
	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	// Create and set up test users where UIN is the same as IdentScreenName
	user1 := User{
		IdentScreenName: NewIdentScreenName("12345"),
	}
	err = f.InsertUser(context.Background(), user1)
	assert.NoError(t, err)

	user2 := User{
		IdentScreenName: NewIdentScreenName("67890"),
	}
	err = f.InsertUser(context.Background(), user2)
	assert.NoError(t, err)

	user3 := User{
		IdentScreenName: NewIdentScreenName("54321"),
	}
	err = f.InsertUser(context.Background(), user3)
	assert.NoError(t, err)

	t.Run("Find User by UIN", func(t *testing.T) {
		// Search for user with UIN 12345
		user, err := f.FindByUIN(context.Background(), 12345)
		assert.NoError(t, err)
		assert.Equal(t, user1.IdentScreenName, user.IdentScreenName)

		// Search for user with UIN 67890
		user, err = f.FindByUIN(context.Background(), 67890)
		assert.NoError(t, err)
		assert.Equal(t, user2.IdentScreenName, user.IdentScreenName)

		// Search for user with UIN 54321
		user, err = f.FindByUIN(context.Background(), 54321)
		assert.NoError(t, err)
		assert.Equal(t, user3.IdentScreenName, user.IdentScreenName)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Search for a UIN that doesn't exist
		_, err := f.FindByUIN(context.Background(), 99999)
		assert.ErrorIs(t, err, ErrNoUser)
	})
}

func TestSQLiteUserStore_RetrieveMessages(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	createStubUser := func(t *testing.T, store SQLiteUserStore, screenName DisplayScreenName) {
		t.Helper()
		user := User{
			IdentScreenName:   NewIdentScreenName(string(screenName)),
			DisplayScreenName: screenName,
			AuthKey:           uuid.New().String(),
			IsICQ:             screenName.IsUIN(),
		}
		require.NoError(t, user.HashPassword("welcome1"))
		require.NoError(t, store.InsertUser(context.Background(), user))
	}

	createStubUser(t, *f, DisplayScreenName("John"))
	createStubUser(t, *f, DisplayScreenName("Jack"))
	createStubUser(t, *f, DisplayScreenName("Anne"))

	sendTime := time.Now().UTC()

	offlineMessages := []OfflineMessage{
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Jack"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 1,
			},
			Sent: sendTime,
		},
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Anne"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 2,
			},
			Sent: sendTime,
		},
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Jack"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 3,
			},
			Sent: sendTime,
		},
	}

	expectedCounts := []int{1, 1, 2}
	for i, msg := range offlineMessages {
		count, err := f.SaveMessage(context.Background(), msg)
		assert.NoError(t, err)
		assert.Equal(t, expectedCounts[i], count)

		// Verify offlineMsgCount is updated in the database
		recipient, err := f.User(context.Background(), msg.Recipient)
		assert.NoError(t, err)
		assert.NotNil(t, recipient)
		assert.Equal(t, expectedCounts[i], recipient.OfflineMsgCount)
	}

	t.Run("Retrieve Messages", func(t *testing.T) {
		messages, err := f.RetrieveMessages(context.Background(), NewIdentScreenName("Jack"))
		assert.NoError(t, err)
		if assert.Len(t, messages, 2) {
			assert.Equal(t, offlineMessages[0], messages[0])
			assert.Equal(t, offlineMessages[2], messages[1])
		}
	})

	t.Run("Retrieve No Messages", func(t *testing.T) {
		messages, err := f.RetrieveMessages(context.Background(), NewIdentScreenName("Franke"))
		assert.NoError(t, err)
		assert.Empty(t, messages)
	})
}

func TestSQLiteUserStore_DeleteMessages(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	createStubUser := func(t *testing.T, store SQLiteUserStore, screenName DisplayScreenName) {
		t.Helper()
		user := User{
			IdentScreenName:   NewIdentScreenName(string(screenName)),
			DisplayScreenName: screenName,
			AuthKey:           uuid.New().String(),
			IsICQ:             screenName.IsUIN(),
		}
		require.NoError(t, user.HashPassword("welcome1"))
		require.NoError(t, store.InsertUser(context.Background(), user))
	}

	createStubUser(t, *f, DisplayScreenName("John"))
	createStubUser(t, *f, DisplayScreenName("Jack"))
	createStubUser(t, *f, DisplayScreenName("Anne"))

	sendTime := time.Now().UTC()

	offlineMessages := []OfflineMessage{
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Jack"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 1,
			},
			Sent: sendTime,
		},
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Anne"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 2,
			},
			Sent: sendTime,
		},
		{
			Sender:    NewIdentScreenName("John"),
			Recipient: NewIdentScreenName("Jack"),
			Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				Cookie: 3,
			},
			Sent: sendTime,
		},
	}

	expectedCounts := []int{1, 1, 2}
	for i, msg := range offlineMessages {
		count, err := f.SaveMessage(context.Background(), msg)
		assert.NoError(t, err)
		assert.Equal(t, expectedCounts[i], count)

		// Verify offlineMsgCount is updated in the database
		recipient, err := f.User(context.Background(), msg.Recipient)
		assert.NoError(t, err)
		assert.NotNil(t, recipient)
		assert.Equal(t, expectedCounts[i], recipient.OfflineMsgCount)
	}

	t.Run("Delete Messages", func(t *testing.T) {
		err := f.DeleteMessages(context.Background(), NewIdentScreenName("Jack"))
		assert.NoError(t, err)

		messages, err := f.RetrieveMessages(context.Background(), NewIdentScreenName("Jack"))
		assert.NoError(t, err)
		assert.Empty(t, messages)

		messages, err = f.RetrieveMessages(context.Background(), NewIdentScreenName("Anne"))
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
	})

	t.Run("Delete No Messages", func(t *testing.T) {
		err := f.DeleteMessages(context.Background(), NewIdentScreenName("Franke"))
		assert.NoError(t, err)

		messages, err := f.RetrieveMessages(context.Background(), NewIdentScreenName("Anne"))
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
	})
}

func TestSQLiteUserStore_SaveMessage(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	store, err := NewSQLiteUserStore(testFile)
	require.NoError(t, err)

	createStubUser := func(t *testing.T, store SQLiteUserStore, screenName DisplayScreenName) {
		t.Helper()
		user := User{
			IdentScreenName:   NewIdentScreenName(string(screenName)),
			DisplayScreenName: screenName,
			AuthKey:           uuid.New().String(),
			IsICQ:             screenName.IsUIN(),
		}
		require.NoError(t, user.HashPassword("welcome1"))
		require.NoError(t, store.InsertUser(context.Background(), user))
	}
	createStubUser(t, *store, DisplayScreenName("Sender"))
	createStubUser(t, *store, DisplayScreenName("Recipient"))

	msg := OfflineMessage{
		Sender:    NewIdentScreenName("Sender"),
		Recipient: NewIdentScreenName("Recipient"),
		Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			Cookie: 42,
		},
		Sent: time.Now().UTC(),
	}

	t.Run("within limit", func(t *testing.T) {
		for i := 1; i <= offlineInboxLimit; i++ {
			count, err := store.SaveMessage(context.Background(), msg)
			require.NoError(t, err)
			require.Equal(t, i, count)

			// Verify offlineMsgCount is updated in the database
			recipient, err := store.User(context.Background(), msg.Recipient)
			require.NoError(t, err)
			require.NotNil(t, recipient)
			require.Equal(t, i, recipient.OfflineMsgCount)
		}
	})

	t.Run("limit exceeded", func(t *testing.T) {
		_, err := store.SaveMessage(context.Background(), msg)
		require.ErrorIs(t, err, ErrOfflineInboxFull)
	})

	t.Run("missing sender", func(t *testing.T) {
		missingSenderMsg := OfflineMessage{
			Sender:    NewIdentScreenName("UnknownSender"),
			Recipient: NewIdentScreenName("Recipient"),
			Message:   msg.Message,
			Sent:      time.Now().UTC(),
		}
		_, err := store.SaveMessage(context.Background(), missingSenderMsg)
		require.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("missing recipient", func(t *testing.T) {
		missingRecipientMsg := OfflineMessage{
			Sender:    NewIdentScreenName("Sender"),
			Recipient: NewIdentScreenName("UnknownRecipient"),
			Message:   msg.Message,
			Sent:      time.Now().UTC(),
		}
		_, err := store.SaveMessage(context.Background(), missingRecipientMsg)
		require.ErrorIs(t, err, ErrNoUser)
	})
}

func TestSQLiteUserStore_BuddyIconMetadataExistingRef(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()
	screenName := NewIdentScreenName("TalkingTyler")
	testHash := []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'}

	feedbagStore, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	itemsIn := []wire.FeedbagItem{
		{
			Name:    "1",
			ClassID: wire.FeedbagClassIdBart,
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
						Hash: testHash,
					}),
				},
			},
		},
	}
	if err := feedbagStore.FeedbagUpsert(context.Background(), screenName, itemsIn); err != nil {
		t.Fatalf("failed to upsert: %s", err.Error())
	}

	b, err := feedbagStore.BuddyIconMetadata(context.Background(), screenName)
	assert.NoError(t, err)

	if !reflect.DeepEqual(b.BARTInfo.Hash, testHash) {
		t.Fatalf("expected hash did not match")
	}
}

func TestSQLiteUserStore_BuddyIconMetadataMissingRef(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	existingScreenName := NewIdentScreenName("TalkingTyler")
	queryScreenName := NewIdentScreenName("SingingSuzy")
	testHash := []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'}

	feedbagStore, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	itemsIn := []wire.FeedbagItem{
		{
			Name:    "1",
			ClassID: wire.FeedbagClassIdBart,
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
						Hash: testHash,
					}),
				},
			},
		},
	}
	if err := feedbagStore.FeedbagUpsert(context.Background(), existingScreenName, itemsIn); err != nil {
		t.Fatalf("failed to upsert: %s", err.Error())
	}

	b, err := feedbagStore.BuddyIconMetadata(context.Background(), queryScreenName)
	assert.NoError(t, err)

	if b != nil {
		t.Fatalf("empty BARTID expected")
	}
}

func TestSQLiteUserStore_SetDirectoryInfo(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("testuser")
	user := User{
		IdentScreenName: screenName,
	}
	err = f.InsertUser(context.Background(), user)
	assert.NoError(t, err)

	directoryInfo := AIMNameAndAddr{
		FirstName:  "John",
		LastName:   "Doe",
		MiddleName: "Michael",
		MaidenName: "Smith",
		Country:    "USA",
		State:      "CA",
		City:       "San Francisco",
		NickName:   "Johnny",
		ZIPCode:    "94105",
		Address:    "123 Main St",
	}

	t.Run("Successful Update", func(t *testing.T) {
		err := f.SetDirectoryInfo(context.Background(), screenName, directoryInfo)
		assert.NoError(t, err)

		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, directoryInfo.FirstName, updatedUser.AIMDirectoryInfo.FirstName)
		assert.Equal(t, directoryInfo.LastName, updatedUser.AIMDirectoryInfo.LastName)
		assert.Equal(t, directoryInfo.MiddleName, updatedUser.AIMDirectoryInfo.MiddleName)
		assert.Equal(t, directoryInfo.MaidenName, updatedUser.AIMDirectoryInfo.MaidenName)
		assert.Equal(t, directoryInfo.Country, updatedUser.AIMDirectoryInfo.Country)
		assert.Equal(t, directoryInfo.State, updatedUser.AIMDirectoryInfo.State)
		assert.Equal(t, directoryInfo.City, updatedUser.AIMDirectoryInfo.City)
		assert.Equal(t, directoryInfo.NickName, updatedUser.AIMDirectoryInfo.NickName)
		assert.Equal(t, directoryInfo.ZIPCode, updatedUser.AIMDirectoryInfo.ZIPCode)
		assert.Equal(t, directoryInfo.Address, updatedUser.AIMDirectoryInfo.Address)
	})

	t.Run("Update Non-Existing User", func(t *testing.T) {
		nonExistingScreenName := NewIdentScreenName("nonexistentuser")
		err := f.SetDirectoryInfo(context.Background(), nonExistingScreenName, directoryInfo)

		assert.ErrorIs(t, err, ErrNoUser)
	})

	t.Run("Empty Directory Info", func(t *testing.T) {
		emptyDirectoryInfo := AIMNameAndAddr{}
		err := f.SetDirectoryInfo(context.Background(), screenName, emptyDirectoryInfo)
		assert.NoError(t, err)

		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.FirstName)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.LastName)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.MiddleName)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.MaidenName)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.Country)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.State)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.City)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.NickName)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.ZIPCode)
		assert.Empty(t, updatedUser.AIMDirectoryInfo.Address)
	})
}

func TestSQLiteUserStore_Categories(t *testing.T) {
	t.Run("Retrieve Keyword Categories Successfully", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Insert some test keyword categories
		categories := []string{"Category3", "Category1", "Category2"}
		for _, categoryName := range categories {
			_, err := f.CreateCategory(context.Background(), categoryName)
			assert.NoError(t, err)
		}

		retrievedCategories, err := f.Categories(context.Background())
		assert.NoError(t, err)

		// Make sure all categories are returned in alphabetical order
		if assert.Len(t, retrievedCategories, len(categories)) {
			expect := []Category{
				{
					ID:   2,
					Name: "Category1",
				},
				{
					ID:   3,
					Name: "Category2",
				},
				{
					ID:   1,
					Name: "Category3",
				},
			}
			assert.Equal(t, expect, retrievedCategories)
		}
	})

	t.Run("No Categories Exist", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Clean up the database
		_, err = f.db.Exec(`DELETE FROM aimKeywordCategory`)
		assert.NoError(t, err)

		retrievedCategories, err := f.Categories(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, retrievedCategories)
	})

	t.Run("SQL Error Handling", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Force an error by querying a non-existent table
		_, err = f.db.Exec(`DROP TABLE aimKeywordCategory`)
		assert.NoError(t, err)

		_, err = f.Categories(context.Background())
		assert.Error(t, err)
	})

	t.Run("Unique Constraint Violation", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Insert a category with a unique name
		categoryName := "UniqueCategory"
		_, err = f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Try to insert the same category name again to trigger the unique constraint
		_, err = f.CreateCategory(context.Background(), categoryName)
		assert.ErrorIs(t, err, ErrKeywordCategoryExists)
	})
}

func TestSQLiteUserStore_CreateCategory(t *testing.T) {
	t.Run("Successfully Create Keyword Category", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		categoryName := "TestCategory"
		keywordCategory, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		assert.Equal(t, categoryName, keywordCategory.Name)
		assert.NotZero(t, keywordCategory.ID)

		categories, err := f.Categories(context.Background())
		assert.NoError(t, err)
		if assert.Len(t, categories, 1) {
			assert.Equal(t, categoryName, categories[0].Name)
		}
	})

	t.Run("Duplicate Category Cookie", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		categoryName := "DuplicateCategory"

		// Create the category
		_, err = f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Try to create the same category again
		_, err = f.CreateCategory(context.Background(), categoryName)
		assert.ErrorIs(t, err, ErrKeywordCategoryExists)
	})

	t.Run("ID Overflow", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Simulate ID overflow by inserting max number of entries
		for i := range math.MaxUint8 {
			_, err := f.CreateCategory(context.Background(), fmt.Sprintf("Category_%d", i))
			assert.NoError(t, err)
		}

		// Next insert should cause an ID overflow
		_, err = f.CreateCategory(context.Background(), "OverflowCategory")
		assert.ErrorIs(t, err, errTooManyCategories)
	})

	t.Run("SQL Error Handling", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Drop the table to cause an error
		_, err = f.db.Exec(`DROP TABLE aimKeywordCategory`)
		assert.NoError(t, err)

		_, err = f.CreateCategory(context.Background(), "ShouldFail")
		assert.Error(t, err)
	})
}

func TestSQLiteUserStore_DeleteCategory(t *testing.T) {
	t.Run("Successfully Delete Keyword Category", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Insert a test category
		categoryName := "CategoryToDelete"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Ensure the category was created
		retrievedCategories, err := f.Categories(context.Background())
		assert.NoError(t, err)
		assert.Len(t, retrievedCategories, 1)

		// Delete the category
		err = f.DeleteCategory(context.Background(), category.ID)
		assert.NoError(t, err)

		// Verify the category was deleted
		retrievedCategories, err = f.Categories(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, retrievedCategories)
	})

	t.Run("Delete Non-Existent Category", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Attempt to delete a category that does not exist
		nonExistentCategoryID := uint8(99)
		err = f.DeleteCategory(context.Background(), nonExistentCategoryID)
		assert.ErrorIs(t, err, ErrKeywordCategoryNotFound)
	})

	t.Run("Delete category and all of its keywords", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Insert a category
		categoryName := "CategoryInUse"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Insert a keyword that references this category
		keywordName := "KeywordInUse"
		_, err = f.CreateKeyword(context.Background(), keywordName, category.ID)
		assert.NoError(t, err)

		// Create a user and associate it with the keyword
		u := User{
			IdentScreenName: NewIdentScreenName("testuser"),
		}
		err = f.InsertUser(context.Background(), u)
		assert.NoError(t, err)

		err = f.SetKeywords(context.Background(), u.IdentScreenName, [5]string{keywordName})
		assert.NoError(t, err)

		// Attempt to delete the category that is in use by the keyword
		err = f.DeleteCategory(context.Background(), category.ID)
		assert.ErrorIs(t, err, ErrKeywordInUse)
	})
}

func TestSQLiteUserStore_CreateKeyword(t *testing.T) {
	t.Run("Successfully Create Keyword", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Create a test category
		categoryName := "TestCategory"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Insert a keyword for the category
		keywordName := "TestKeyword"
		keyword, err := f.CreateKeyword(context.Background(), keywordName, category.ID)
		assert.NoError(t, err)

		assert.Equal(t, keywordName, keyword.Name)
		assert.NotZero(t, keyword.ID)

		// Verify the keyword and category were inserted into the database
		keywords, err := f.KeywordsByCategory(context.Background(), category.ID)
		assert.NoError(t, err)
		if assert.Len(t, keywords, 1) {
			expect := []Keyword{
				keyword,
			}
			assert.Equal(t, expect, keywords)
		}
	})

	t.Run("Create Keyword Without Category", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Insert a keyword with no category (parent is NULL)
		keywordName := "UncategorizedKeyword"
		keyword, err := f.CreateKeyword(context.Background(), keywordName, 0)
		assert.NoError(t, err)

		assert.Equal(t, keywordName, keyword.Name)
		assert.NotZero(t, keyword.ID)

		// Verify the keyword was inserted into the database
		keywords, err := f.KeywordsByCategory(context.Background(), 0)
		assert.NoError(t, err)
		if assert.Len(t, keywords, 1) {
			expect := []Keyword{
				keyword,
			}
			assert.Equal(t, expect, keywords)
		}
	})

	t.Run("Create Keyword With Unknown Category", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Insert a keyword with no category (parent is NULL)
		keywordName := "AKeyword"
		_, err = f.CreateKeyword(context.Background(), keywordName, 1)
		assert.ErrorIs(t, err, ErrKeywordCategoryNotFound)
	})

	t.Run("Duplicate Keyword Cookie", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		keywordName := "DuplicateKeyword"

		// Create the keyword
		_, err = f.CreateKeyword(context.Background(), keywordName, 0)
		assert.NoError(t, err)

		// Try to create the same keyword again
		_, err = f.CreateKeyword(context.Background(), keywordName, 0)
		assert.ErrorIs(t, err, ErrKeywordExists)
	})

	t.Run("ID Overflow", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Create a test category
		categoryName := "OverflowCategory"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Simulate ID overflow by inserting max number of entries
		for i := 0; i < math.MaxUint8; i++ {
			_, err := f.CreateKeyword(context.Background(), fmt.Sprintf("Keyword_%d", i), category.ID)
			assert.NoError(t, err)
		}

		// Next insert should cause an ID overflow
		_, err = f.CreateKeyword(context.Background(), "OverflowKeyword", category.ID)
		assert.ErrorIs(t, err, errTooManyKeywords)
	})

	t.Run("SQL Error Handling", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Drop the table to cause an error
		_, err = f.db.Exec(`DROP TABLE aimKeyword`)
		assert.NoError(t, err)

		_, err = f.CreateKeyword(context.Background(), "ShouldFail", 0)
		assert.Error(t, err)
	})
}

func TestSQLiteUserStore_DeleteKeyword(t *testing.T) {
	t.Run("Successfully Delete Keyword", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Insert a category
		categoryName := "TestCategory"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Insert a keyword for the category
		keywordName := "TestKeyword"
		keyword, err := f.CreateKeyword(context.Background(), keywordName, category.ID)
		assert.NoError(t, err)

		// Ensure the keyword was created
		retrievedKeywords, err := f.KeywordsByCategory(context.Background(), category.ID)
		assert.NoError(t, err)
		assert.Len(t, retrievedKeywords, 1)

		// Delete the keyword
		err = f.DeleteKeyword(context.Background(), keyword.ID)
		assert.NoError(t, err)

		// Verify the keyword was deleted
		retrievedKeywords, err = f.KeywordsByCategory(context.Background(), category.ID)
		assert.NoError(t, err)
		assert.Empty(t, retrievedKeywords)
	})

	t.Run("Delete Non-Existent Keyword", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Attempt to delete a keyword that does not exist
		nonExistentKeywordID := uint8(99)
		err = f.DeleteKeyword(context.Background(), nonExistentKeywordID)
		assert.ErrorIs(t, err, ErrKeywordNotFound)
	})

	t.Run("Delete Keyword Associated with User", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		// Insert a category
		categoryName := "CategoryInUse"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		// Insert a keyword
		keywordName := "KeywordInUse"
		keyword, err := f.CreateKeyword(context.Background(), keywordName, category.ID)
		assert.NoError(t, err)

		// Create a user and associate it with the keyword
		u := User{
			IdentScreenName: NewIdentScreenName("testuser"),
		}
		err = f.InsertUser(context.Background(), u)
		assert.NoError(t, err)

		err = f.SetKeywords(context.Background(), u.IdentScreenName, [5]string{keywordName})
		assert.NoError(t, err)

		// Attempt to delete the keyword and expect an ErrKeywordInUse
		err = f.DeleteKeyword(context.Background(), keyword.ID)
		assert.ErrorIs(t, err, ErrKeywordInUse)
	})
}

func TestSQLiteUserStore_InterestList(t *testing.T) {
	t.Run("Full list", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		tech, err := f.CreateCategory(context.Background(), "Technology")
		assert.NoError(t, err)
		music, err := f.CreateCategory(context.Background(), "Music")
		assert.NoError(t, err)
		sports, err := f.CreateCategory(context.Background(), "Sports")
		assert.NoError(t, err)

		_, err = f.CreateKeyword(context.Background(), "Rock", music.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Soccer", sports.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Cybersecurity", tech.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Zoology", 0)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Jazz", music.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Animals", 0)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Basketball", sports.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Artificial Intelligence", tech.ID)
		assert.NoError(t, err)
		_, err = f.CreateKeyword(context.Background(), "Tennis", sports.ID)
		assert.NoError(t, err)

		expect := []wire.ODirKeywordListItem{
			{
				ID:   0,
				Name: "Animals",
				Type: wire.ODirKeyword,
			},
			{
				ID:   2,
				Name: "Music",
				Type: wire.ODirKeywordCategory,
			},
			{
				ID:   2,
				Name: "Jazz",
				Type: wire.ODirKeyword,
			},
			{
				ID:   2,
				Name: "Rock",
				Type: wire.ODirKeyword,
			},
			{
				ID:   3,
				Name: "Sports",
				Type: wire.ODirKeywordCategory,
			},
			{
				ID:   3,
				Name: "Basketball",
				Type: wire.ODirKeyword,
			},
			{
				ID:   3,
				Name: "Soccer",
				Type: wire.ODirKeyword,
			},
			{
				ID:   3,
				Name: "Tennis",
				Type: wire.ODirKeyword,
			},
			{
				ID:   1,
				Name: "Technology",
				Type: wire.ODirKeywordCategory,
			},
			{
				ID:   1,
				Name: "Artificial Intelligence",
				Type: wire.ODirKeyword,
			},
			{
				ID:   1,
				Name: "Cybersecurity",
				Type: wire.ODirKeyword,
			},
			{
				ID:   0,
				Name: "Zoology",
				Type: wire.ODirKeyword,
			},
		}

		actual, err := f.InterestList(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, expect, actual)
	})

	t.Run("Empty list list", func(t *testing.T) {
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		actual, err := f.InterestList(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}

func TestSQLiteUserStore_KeywordsByCategory(t *testing.T) {
	t.Run("Category Does Not Exist", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()
		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		// Create a test category
		categoryName := "TestCategory"
		category, err := f.CreateCategory(context.Background(), categoryName)
		assert.NoError(t, err)

		keywords, err := f.KeywordsByCategory(context.Background(), category.ID+1)
		assert.Empty(t, keywords)
		assert.ErrorIs(t, err, ErrKeywordCategoryNotFound)
	})
}

func TestSQLiteUserStore_UnregisterBuddyList(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	users := []IdentScreenName{
		NewIdentScreenName("user1"),
		NewIdentScreenName("user2"),
		NewIdentScreenName("user3"),
	}

	for _, me := range users {
		err = f.RegisterBuddyList(context.Background(), me)
		assert.NoError(t, err)
		for _, them := range users {
			if me == them {
				continue
			}
			err = f.AddBuddy(context.Background(), me, them)
			assert.NoError(t, err)
		}
	}

	relationships, err := f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	expect := []Relationship{
		{
			User:          NewIdentScreenName("user2"),
			IsOnTheirList: true,
			IsOnYourList:  true,
		},
		{
			User:          NewIdentScreenName("user3"),
			IsOnTheirList: true,
			IsOnYourList:  true,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	err = f.UnregisterBuddyList(context.Background(), users[2])
	assert.NoError(t, err)

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)
	expect = []Relationship{
		{
			User:          NewIdentScreenName("user2"),
			IsOnTheirList: true,
			IsOnYourList:  true,
		},
	}
	assert.ElementsMatch(t, relationships, expect)
}

func TestSQLiteUserStore_ClearBuddyListRegistry(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	users := []IdentScreenName{
		NewIdentScreenName("user1"),
		NewIdentScreenName("user2"),
		NewIdentScreenName("user3"),
	}

	for _, me := range users {
		err = f.RegisterBuddyList(context.Background(), me)
		assert.NoError(t, err)
		for _, them := range users {
			if me == them {
				continue
			}
			err = f.AddBuddy(context.Background(), me, them)
			assert.NoError(t, err)
		}
	}

	for _, me := range users {
		var relationships []Relationship
		relationships, err = f.AllRelationships(context.Background(), me, nil)
		assert.NoError(t, err)
		assert.Len(t, relationships, 2)
	}

	err = f.ClearBuddyListRegistry(context.Background())
	assert.NoError(t, err)

	for _, me := range users {
		var relationships []Relationship
		relationships, err = f.AllRelationships(context.Background(), me, nil)
		assert.NoError(t, err)
		assert.Empty(t, relationships)
	}
}

func TestSQLiteUserStore_RemoveBuddy(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	me := NewIdentScreenName("me")
	err = f.RegisterBuddyList(context.Background(), me)
	assert.NoError(t, err)

	them := NewIdentScreenName("them")
	err = f.RegisterBuddyList(context.Background(), them)
	assert.NoError(t, err)

	err = f.AddBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err := f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect := []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  true,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	err = f.RemoveBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err = f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect = []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)
}

func TestSQLiteUserStore_RemoveDenyBuddy(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	me := NewIdentScreenName("me")
	err = f.RegisterBuddyList(context.Background(), me)
	assert.NoError(t, err)
	err = f.SetPDMode(context.Background(), me, wire.FeedbagPDModeDenySome)
	assert.NoError(t, err)

	them := NewIdentScreenName("them")
	err = f.RegisterBuddyList(context.Background(), them)
	assert.NoError(t, err)

	err = f.DenyBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err := f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect := []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      true,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	err = f.RemoveDenyBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err = f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect = []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)
}

func TestSQLiteUserStore_RemovePermitBuddy(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	me := NewIdentScreenName("me")
	err = f.RegisterBuddyList(context.Background(), me)
	assert.NoError(t, err)
	err = f.SetPDMode(context.Background(), me, wire.FeedbagPDModePermitSome)
	assert.NoError(t, err)

	them := NewIdentScreenName("them")
	err = f.RegisterBuddyList(context.Background(), them)
	assert.NoError(t, err)

	err = f.PermitBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err := f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect := []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	err = f.RemovePermitBuddy(context.Background(), me, them)
	assert.NoError(t, err)

	relationships, err = f.AllRelationships(context.Background(), me, nil)
	assert.NoError(t, err)

	expect = []Relationship{
		{
			User:          them,
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      true,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)
}

func TestSQLiteUserStore_SetPDMode(t *testing.T) {
	t.Run("Ensure idempotency", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		users := []IdentScreenName{
			NewIdentScreenName("me"),
			NewIdentScreenName("them1"),
		}
		for _, user := range users {
			err = f.RegisterBuddyList(context.Background(), user)
			assert.NoError(t, err)
		}

		assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitSome))
		assert.NoError(t, f.PermitBuddy(context.Background(), users[0], users[1]))
		assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitSome))

		relationships, err := f.AllRelationships(context.Background(), users[0], nil)
		assert.NoError(t, err)

		expect := []Relationship{
			{
				User:          users[1],
				IsOnTheirList: false,
				IsOnYourList:  false,
				YouBlock:      false,
				BlocksYou:     false,
			},
		}
		assert.ElementsMatch(t, relationships, expect)
	})

	t.Run("Ensure transition from one mode to another clears previously set flags", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		users := []IdentScreenName{
			NewIdentScreenName("me"),
			NewIdentScreenName("them1"),
		}
		for _, user := range users {
			err = f.RegisterBuddyList(context.Background(), user)
			assert.NoError(t, err)
		}

		assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitSome))
		assert.NoError(t, f.PermitBuddy(context.Background(), users[0], users[1]))
		assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModeDenySome))

		relationships, err := f.AllRelationships(context.Background(), users[0], nil)
		assert.NoError(t, err)
		assert.Empty(t, relationships)
	})
}

// Ensure that transitioning between all the PD modes works.
func TestSQLiteUserStore_PermitDenyTransitionIntegration(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	users := []IdentScreenName{
		NewIdentScreenName("me"),
		NewIdentScreenName("them1"),
		NewIdentScreenName("them2"),
		NewIdentScreenName("them3"),
	}
	for _, user := range users {
		err = f.RegisterBuddyList(context.Background(), user)
		assert.NoError(t, err)
	}

	// add them1 to buddy list
	assert.NoError(t, f.AddBuddy(context.Background(), users[0], users[1]))

	// permit them2
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitSome))
	assert.NoError(t, f.PermitBuddy(context.Background(), users[0], users[2]))

	relationships, err := f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is blocked and them2 is permitted
	expect := []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      true,
			BlocksYou:     false,
		},
		{
			User:          users[2],
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// allow everyone
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitAll))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure buddy1 is on your buddy list and permitted
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// permit them3
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitSome))
	assert.NoError(t, f.PermitBuddy(context.Background(), users[0], users[3]))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is blocked them3 is permitted
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      true,
			BlocksYou:     false,
		},
		{
			User:          users[3],
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// only allow on buddy list
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitOnList))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure buddy1 is on your buddy list and permitted
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// deny them2
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModeDenySome))
	assert.NoError(t, f.DenyBuddy(context.Background(), users[0], users[2]))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is allowed and them2 is blocked
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
		{
			User:          users[2],
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      true,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// allow everyone
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitAll))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure buddy1 is on your buddy list and permitted
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// deny them3
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModeDenySome))
	assert.NoError(t, f.DenyBuddy(context.Background(), users[0], users[3]))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is allowed and them3 is blocked
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
		{
			User:          users[3],
			IsOnTheirList: false,
			IsOnYourList:  false,
			YouBlock:      true,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// deny everyone
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModeDenyAll))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is blocked
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      true,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)

	// allow everyone
	assert.NoError(t, f.SetPDMode(context.Background(), users[0], wire.FeedbagPDModePermitAll))

	relationships, err = f.AllRelationships(context.Background(), users[0], nil)
	assert.NoError(t, err)

	// make sure them1 is on your buddy list and permitted
	expect = []Relationship{
		{
			User:          users[1],
			IsOnTheirList: false,
			IsOnYourList:  true,
			YouBlock:      false,
			BlocksYou:     false,
		},
	}
	assert.ElementsMatch(t, relationships, expect)
}

func TestSQLiteUserStore_UpdateSuspendedStatus(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("userA")

	insertedUser := &User{
		IdentScreenName:   screenName,
		DisplayScreenName: DisplayScreenName("usera"),
		AuthKey:           "theauthkey",
		StrongMD5Pass:     []byte("thepasshash"),
		RegStatus:         3,
		SuspendedStatus:   wire.LoginErrSuspendedAccount,
	}
	err = f.InsertUser(context.Background(), *insertedUser)
	assert.NoError(t, err)

	err = f.UpdateSuspendedStatus(context.Background(), wire.LoginErrSuspendedAccountAge, screenName)
	assert.NoError(t, err)

	user, err := f.User(context.Background(), screenName)
	assert.NoError(t, err)

	assert.Equal(t, user.SuspendedStatus, wire.LoginErrSuspendedAccountAge)
}

func TestSQLiteUserStore_SetBotStatus(t *testing.T) {
	defer func() {
		assert.NoError(t, os.Remove(testFile))
	}()

	f, err := NewSQLiteUserStore(testFile)
	assert.NoError(t, err)

	screenName := NewIdentScreenName("userA")

	insertedUser := &User{
		IdentScreenName:   screenName,
		DisplayScreenName: DisplayScreenName("usera"),
		AuthKey:           "theauthkey",
		StrongMD5Pass:     []byte("thepasshash"),
		IsBot:             false,
	}
	err = f.InsertUser(context.Background(), *insertedUser)
	assert.NoError(t, err)

	user, err := f.User(context.Background(), screenName)
	assert.NoError(t, err)
	assert.False(t, user.IsBot)

	err = f.SetBotStatus(context.Background(), true, screenName)
	assert.NoError(t, err)

	user, err = f.User(context.Background(), screenName)
	assert.NoError(t, err)
	assert.True(t, user.IsBot)

	err = f.SetBotStatus(context.Background(), false, screenName)
	assert.NoError(t, err)

	user, err = f.User(context.Background(), screenName)
	assert.NoError(t, err)
	assert.False(t, user.IsBot)
}

func TestSQLiteUserStore_SetWarnLevel(t *testing.T) {
	t.Run("Happy Path - Update Warning Level for Existing User", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		screenName := NewIdentScreenName("testuser")
		user := User{
			IdentScreenName: screenName,
		}
		err = f.InsertUser(context.Background(), user)
		assert.NoError(t, err)

		// Set initial warning level
		lastWarnUpdate := time.Date(2023, 12, 1, 10, 30, 0, 0, time.UTC)
		lastWarnLevel := uint16(5)

		err = f.SetWarnLevel(context.Background(), screenName, lastWarnUpdate, lastWarnLevel)
		assert.NoError(t, err)

		// Verify the warning level was updated
		updatedUser, err := f.User(context.Background(), screenName)
		assert.NoError(t, err)
		assert.Equal(t, lastWarnUpdate, updatedUser.LastWarnUpdate)
		assert.Equal(t, lastWarnLevel, updatedUser.LastWarnLevel)
	})

	t.Run("User Does Not Exist", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		assert.NoError(t, err)

		nonExistentScreenName := NewIdentScreenName("nonexistentuser")
		lastWarnUpdate := time.Date(2023, 12, 1, 10, 30, 0, 0, time.UTC)
		lastWarnLevel := uint16(5)

		err = f.SetWarnLevel(context.Background(), nonExistentScreenName, lastWarnUpdate, lastWarnLevel)
		assert.ErrorIs(t, err, ErrNoUser)
	})
}

func TestSQLiteUserStore_DeleteBARTItem(t *testing.T) {
	t.Run("delete_existing_item", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		require.NoError(t, err)

		ctx := context.Background()

		// Insert a BART item first
		hash := []byte("testhash123456")
		image := []byte("test image data")
		bartType := uint16(1)

		err = f.InsertBARTItem(ctx, hash, image, bartType)
		require.NoError(t, err)

		// Verify it exists
		items, err := f.ListBARTItems(ctx, 1)
		require.NoError(t, err)
		require.Len(t, items, 1)

		// Delete the item
		err = f.DeleteBARTItem(ctx, hash)
		assert.NoError(t, err)

		// Verify it's gone
		items, err = f.ListBARTItems(ctx, 1)
		require.NoError(t, err)
		assert.Len(t, items, 0)
	})

	t.Run("delete_nonexistent_item", func(t *testing.T) {
		defer func() {
			assert.NoError(t, os.Remove(testFile))
		}()

		f, err := NewSQLiteUserStore(testFile)
		require.NoError(t, err)

		ctx := context.Background()
		hash := []byte("nonexistent")

		err = f.DeleteBARTItem(ctx, hash)
		assert.ErrorIs(t, err, ErrBARTItemNotFound)
	})
}
