package state

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/retro-aim-server/wire"
)

func TestSQLiteUserStore_AllRelationships(t *testing.T) {
	// buddyList represents the contents of a client-side or server-side buddy list
	type buddyList struct {
		// privacyMode is your current privacy mode.
		privacyMode wire.FeedbagPDMode
		// buddyList is the list of users on the buddy list. only active for wire.FeedbagPDModePermitAll and wire.FeedbagPDModePermitOnList
		buddyList []IdentScreenName
		// buddyList is the list of users on the permit list. only active when wire.FeedbagPDModePermitSome is set.
		permitList []IdentScreenName
		// buddyList is the list of users on the deny list. only active when wire.FeedbagPDModeDenySome is set.
		denyList []IdentScreenName
	}

	tests := []struct {
		name            string
		me              IdentScreenName
		clientSideLists map[IdentScreenName]buddyList
		serverSideLists map[IdentScreenName]buddyList
		tempBuddyList   map[IdentScreenName][]IdentScreenName
		expect          []Relationship
		filter          []IdentScreenName
	}{
		{
			name: "[me, client-side]: Allow all users to contact me [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, server-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, server-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, server-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, server-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow all users to contact me [them, server-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow all users to contact me [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow all users to contact me [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow all users to contact me [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow all users to contact me [them, server-side]: Allow only users on my Buddy List",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow all users to contact me [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow all users to contact me [them, server-side]: Allow only the users below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow all users to contact me [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow all users to contact me [them, server-side]: Block all users",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow all users to contact me [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow all users to contact me [them, server-side]: Block the users Below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, server-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, server-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, server-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, server-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only users on my Buddy List [them, server-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only users on my Buddy List [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only users on my Buddy List [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only users on my Buddy List [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only users on my Buddy List [them, server-side]: Allow only users on my Buddy List",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only users on my Buddy List [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only users on my Buddy List [them, server-side]: Allow only the users below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only users on my Buddy List [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only users on my Buddy List [them, server-side]: Block all users",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only users on my Buddy List [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only users on my Buddy List [them, server-side]: Block the users Below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, server-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, server-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, server-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, server-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Allow only the users below [them, server-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only the users below [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only the users below [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only the users below [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only the users below [them, server-side]: Allow only users on my Buddy List",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only the users below [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only the users below [them, server-side]: Allow only the users below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only the users below [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only the users below [them, server-side]: Block all users",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Allow only the users below [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Allow only the users below [them, server-side]: Block the users Below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{NewIdentScreenName("them")},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, server-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, server-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, server-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, server-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block all users [them, server-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block all users [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block all users [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block all users [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block all users [them, server-side]: Allow only users on my Buddy List",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block all users [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block all users [them, server-side]: Allow only the users below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block all users [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block all users [them, server-side]: Block all users",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block all users [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block all users [them, server-side]: Block the users Below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, server-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, server-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, server-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, server-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, client-side]: Block the users Below [them, server-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block the users Below [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block the users Below [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block the users Below [them, client-side]: Allow only users on my Buddy List",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block the users Below [them, server-side]: Allow only users on my Buddy List",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitOnList,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block the users Below [them, client-side]: Allow only the users below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block the users Below [them, server-side]: Allow only the users below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModePermitSome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{NewIdentScreenName("me")},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block the users Below [them, client-side]: Block all users",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block the users Below [them, server-side]: Block all users",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenyAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "[me, server-side]: Block the users Below [them, client-side]: Block the users Below",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name:            "[me, server-side]: Block the users Below [them, server-side]: Block the users Below",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("them")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("them")},
				},
				NewIdentScreenName("them"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("me")},
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them"),
					BlocksYou:     true,
					YouBlock:      true,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "(with filter) [me, client-side]: Allow all users to contact me [them, client-side]: Allow all users to contact me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList: []IdentScreenName{
						NewIdentScreenName("them-1"),
						NewIdentScreenName("them-2"),
					},
					permitList: []IdentScreenName{},
					denyList:   []IdentScreenName{},
				},
				NewIdentScreenName("them-1"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them-2"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them-3"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{},
			filter: []IdentScreenName{
				NewIdentScreenName("them-3"),
				NewIdentScreenName("them-1"),
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them-1"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: false,
					IsOnYourList:  true,
				},
				{
					User:          NewIdentScreenName("them-3"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  false,
				},
			},
		},
		{
			name:            "(filtered) [me, server-side]: Allow all users to contact me [them, server-side]: Allow all users to contact me",
			me:              NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList: []IdentScreenName{
						NewIdentScreenName("them-1"),
						NewIdentScreenName("them-2"),
					},
					permitList: []IdentScreenName{},
					denyList:   []IdentScreenName{},
				},
				NewIdentScreenName("them-1"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them-2"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("them-3"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			filter: []IdentScreenName{
				NewIdentScreenName("them-1"),
				NewIdentScreenName("them-3"),
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("them-1"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: false,
					IsOnYourList:  true,
				},
				{
					User:          NewIdentScreenName("them-3"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  false,
				},
			},
		},
		{
			name: "i have a temp buddy, they don't have me",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("friend1"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("friend1")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("friend2"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			tempBuddyList: map[IdentScreenName][]IdentScreenName{
				NewIdentScreenName("me"): {
					NewIdentScreenName("friend2"),
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("friend1"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
				{
					User:          NewIdentScreenName("friend2"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: false,
					IsOnYourList:  true,
				},
			},
		},
		{
			name: "someone has me as a temp buddy, I don't have them",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("friend1"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("friend1")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
				NewIdentScreenName("friend2"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			tempBuddyList: map[IdentScreenName][]IdentScreenName{
				NewIdentScreenName("friend2"): {
					NewIdentScreenName("me"),
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("friend1"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
				{
					User:          NewIdentScreenName("friend2"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  false,
				},
			},
		},
		{
			name: "I have a temp buddy that I've blocked",
			me:   NewIdentScreenName("me"),
			clientSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("friend1"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{NewIdentScreenName("me")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			serverSideLists: map[IdentScreenName]buddyList{
				NewIdentScreenName("me"): {
					privacyMode: wire.FeedbagPDModeDenySome,
					buddyList:   []IdentScreenName{NewIdentScreenName("friend1")},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{NewIdentScreenName("friend2")},
				},
				NewIdentScreenName("friend2"): {
					privacyMode: wire.FeedbagPDModePermitAll,
					buddyList:   []IdentScreenName{},
					permitList:  []IdentScreenName{},
					denyList:    []IdentScreenName{},
				},
			},
			tempBuddyList: map[IdentScreenName][]IdentScreenName{
				NewIdentScreenName("me"): {
					NewIdentScreenName("friend2"),
				},
			},
			expect: []Relationship{
				{
					User:          NewIdentScreenName("friend1"),
					BlocksYou:     false,
					YouBlock:      false,
					IsOnTheirList: true,
					IsOnYourList:  true,
				},
				{
					User:          NewIdentScreenName("friend2"),
					BlocksYou:     false,
					YouBlock:      true,
					IsOnTheirList: false,
					IsOnYourList:  true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				_ = os.Remove(testFile)
			}()

			feedbagStore, err := NewSQLiteUserStore(testFile)
			assert.NoError(t, err)

			for sn, list := range tt.clientSideLists {
				assert.NoError(t, feedbagStore.SetPDMode(context.Background(), sn, list.privacyMode))
				for _, buddy := range list.buddyList {
					assert.NoError(t, feedbagStore.AddBuddy(context.Background(), sn, buddy))
				}
				for _, buddy := range list.permitList {
					assert.NoError(t, feedbagStore.PermitBuddy(context.Background(), sn, buddy))
				}
				for _, buddy := range list.denyList {
					assert.NoError(t, feedbagStore.DenyBuddy(context.Background(), sn, buddy))
				}
			}

			for sn, list := range tt.serverSideLists {
				assert.NoError(t, feedbagStore.UseFeedbag(context.Background(), sn))
				itemID := uint16(1)
				items := []wire.FeedbagItem{
					pdInfoItem(itemID, list.privacyMode),
				}
				itemID++
				for _, buddy := range list.buddyList {
					items = append(items, newFeedbagItem(wire.FeedbagClassIdBuddy, itemID, buddy.String()))
					itemID++
				}
				for _, buddy := range list.permitList {
					items = append(items, newFeedbagItem(wire.FeedbagClassIDPermit, itemID, buddy.String()))
					itemID++
				}
				for _, buddy := range list.denyList {
					items = append(items, newFeedbagItem(wire.FeedbagClassIDDeny, itemID, buddy.String()))
					itemID++
				}
				assert.NoError(t, feedbagStore.FeedbagUpsert(context.Background(), sn, items))
			}

			for sn, list := range tt.tempBuddyList {
				for _, buddy := range list {
					assert.NoError(t, feedbagStore.AddBuddy(context.Background(), sn, buddy))
				}
			}

			have, err := feedbagStore.AllRelationships(context.Background(), tt.me, tt.filter)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expect, have)
		})
	}
}
