package foodgroup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// omitCaps is the map of to filter out of the client's capability list
// because they are not currently supported by the server.
var omitCaps = map[[16]byte]bool{
	// 0946134a-4c7f-11d1-8222-444553540000 (games)
	{9, 70, 19, 74, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0}: true,
	// 0946134d-4c7f-11d1-8222-444553540000 (ICQ inter-op)
	{9, 70, 19, 77, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0}: true,
	// 09461341-4c7f-11d1-8222-444553540000 (voice chat)
	{9, 70, 19, 65, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0}: true,
}

// NewLocateService creates a new instance of LocateService.
func NewLocateService(
	bartItemManager BARTItemManager,
	messageRelayer MessageRelayer,
	profileManager ProfileManager,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	userManager UserManager,
) LocateService {
	return LocateService{
		buddyBroadcaster:    newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:      messageRelayer,
		relationshipFetcher: relationshipFetcher,
		profileManager:      profileManager,
		sessionRetriever:    sessionRetriever,
		userManager:         userManager,
	}
}

// LocateService provides functionality for the Locate food group, which is
// responsible for user profiles, user info lookups, directory information, and
// keyword lookups.
type LocateService struct {
	buddyBroadcaster    buddyBroadcaster
	messageRelayer      MessageRelayer
	relationshipFetcher RelationshipFetcher
	profileManager      ProfileManager
	sessionRetriever    SessionRetriever
	userManager         UserManager
}

// RightsQuery returns SNAC wire.LocateRightsReply, which contains Locate food
// group settings for the current user.
func (s LocateService) RightsQuery(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateRightsReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x02_0x03_LocateRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					// these are arbitrary values--AIM clients seem to perform
					// OK with them
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxSigLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxCapabilitiesLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxFindByEmailList, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxCertsLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxMaxShortCapabilities, uint16(1000)),
				},
			},
		},
	}
}

// SetInfo sets the user's profile, away message or capabilities.
func (s LocateService) SetInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x02_0x04_LocateSetInfo) error {

	// update profile
	if profileText, hasProfile := inBody.String(wire.LocateTLVTagsInfoSigData); hasProfile {
		mime, _ := inBody.String(wire.LocateTLVTagsInfoSigMime)
		profile := state.UserProfile{
			ProfileText: profileText,
			MIMEType:    mime,
			UpdateTime:  time.Now(),
		}

		// set the server-side profile
		if instance.KerberosAuth() || inBody.HasTag(wire.LocateTLVTagsInfoSupportHostSig) {
			// normally, the SupportHostSig TLV indicates that the profile should
			// be stored server-side. however, some AIM 6 clients expect server-side
			// profiles but do not send this TLV. in order to cover all bases, just
			// save the profile for all kerberos-based clients.
			if err := s.profileManager.SetProfile(ctx, instance.IdentScreenName(), profile); err != nil {
				return err
			}

			for _, _instance := range instance.Session().Instances() {
				if _instance.KerberosAuth() {
					// update all instances that do server-side profile storage
					_instance.SetProfile(profile)
				}
			}

			s.messageRelayer.RelayToOtherInstances(ctx, instance, wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
				},
				Body: newOServiceUserInfoUpdate(instance),
			})
		} else {
			// set the client-side profile
			instance.SetProfile(profile)
		}
	}

	// broadcast away message change to buddies
	if awayMsg, hasAwayMsg := inBody.String(wire.LocateTLVTagsInfoUnavailableData); hasAwayMsg {
		if awayMsg != "" {
			instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
		} else {
			instance.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
		}
		instance.SetAwayMessage(awayMsg)
		if instance.SignonComplete() {
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
				return err
			}
		}
	}

	// update client capabilities (buddy icon, chat, etc...)
	if b, hasCaps := inBody.Bytes(wire.LocateTLVTagsInfoCapabilities); hasCaps {
		if len(b)%16 != 0 {
			return errors.New("capability list must be array of 16-byte values")
		}
		var caps [][16]byte
		for i := 0; i < len(b); i += 16 {
			var c [16]byte
			copy(c[:], b[i:i+16])
			if _, found := omitCaps[c]; found {
				continue
			}
			caps = append(caps, c)
		}
		instance.SetCaps(caps)
		if instance.SignonComplete() {
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
				return err
			}
		}
	}

	return nil
}

func newLocateErr(requestID uint32, errCode uint16) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateErr,
			RequestID: requestID,
		},
		Body: wire.SNACError{
			Code: errCode,
		},
	}
}

// UserInfoQuery fetches display information about an arbitrary user (not the
// current user). It returns wire.LocateUserInfoReply, which contains the
// profile, if requested, and/or the away message, if requested.
func (s LocateService) UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error) {
	lookupSN := state.NewIdentScreenName(inBody.ScreenName)

	var lookupSess *state.Session
	if lookupSN == instance.IdentScreenName() {
		// looking up own profile
		lookupSess = instance.Session()
	} else {
		rel, err := s.relationshipFetcher.Relationship(ctx, instance.IdentScreenName(), lookupSN)
		if err != nil {
			return wire.SNACMessage{}, err
		}

		if rel.YouBlock || rel.BlocksYou {
			return newLocateErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}

		lookupSess = s.sessionRetriever.RetrieveSession(lookupSN)
		if lookupSess == nil {
			// user is offline
			return newLocateErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
	}

	var list wire.TLVList

	if inBody.RequestProfile() {
		prof := lookupSess.Profile()
		// if looking up own profile, return this instance's profile for consistency
		if instance.IdentScreenName() == lookupSN {
			prof = instance.Profile()
		}
		list.AppendList([]wire.TLV{
			wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, prof.MIMEType),
			wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, prof.ProfileText),
		})
	}

	if inBody.RequestAwayMessage() && lookupSess.Away() {
		list.AppendList([]wire.TLV{
			wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableMime, `text/aolrtf; charset="us-ascii"`),
			wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, lookupSess.AwayMessage()),
		})
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateUserInfoReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: lookupSess.TLVUserInfo(),
			LocateInfo: wire.TLVRestBlock{
				TLVList: list,
			},
		},
	}, nil
}

// SetDirInfo sets directory information for current user (first name, last
// name, etc).
func (s LocateService) SetDirInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x09_LocateSetDirInfo) (wire.SNACMessage, error) {
	info := newAIMNameAndAddrFromTLVList(inBody.TLVList)

	if err := s.profileManager.SetDirectoryInfo(ctx, instance.IdentScreenName(), info); err != nil {
		return wire.SNACMessage{}, err
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateSetDirReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x02_0x0A_LocateSetDirReply{
			Result: 1,
		},
	}, nil
}

// SetKeywordInfo sets profile keywords and interests. This method does nothing
// and exists to placate the AIM client. It returns wire.LocateSetKeywordReply
// with a canned success message.
func (s LocateService) SetKeywordInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0F_LocateSetKeywordInfo) (wire.SNACMessage, error) {
	var keywords [5]string

	i := 0
	for _, tlv := range inBody.TLVList {
		if tlv.Tag != wire.ODirTLVInterest {
			continue
		}
		keywords[i] = string(tlv.Value)
		i++
		if i == len(keywords) {
			break
		}
	}

	if err := s.profileManager.SetKeywords(ctx, instance.IdentScreenName(), keywords); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("SetKeywords: %w", err)
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateSetKeywordReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x02_0x10_LocateSetKeywordReply{
			Unknown: 1,
		},
	}, nil
}

// DirInfo returns directory information for a user.
func (s LocateService) DirInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error) {
	reply := wire.SNAC_0x02_0x0C_LocateGetDirReply{
		Status: wire.LocateGetDirReplyOK,
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{},
		},
	}

	user, err := s.profileManager.User(ctx, state.NewIdentScreenName(inBody.ScreenName))
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("User: %w", err)
	}

	if user != nil {
		reply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, user.AIMDirectoryInfo.FirstName))
		reply.Append(wire.NewTLVBE(wire.ODirTLVLastName, user.AIMDirectoryInfo.LastName))
		reply.Append(wire.NewTLVBE(wire.ODirTLVMiddleName, user.AIMDirectoryInfo.MiddleName))
		reply.Append(wire.NewTLVBE(wire.ODirTLVMaidenName, user.AIMDirectoryInfo.MaidenName))
		reply.Append(wire.NewTLVBE(wire.ODirTLVCountry, user.AIMDirectoryInfo.Country))
		reply.Append(wire.NewTLVBE(wire.ODirTLVState, user.AIMDirectoryInfo.State))
		reply.Append(wire.NewTLVBE(wire.ODirTLVCity, user.AIMDirectoryInfo.City))
		reply.Append(wire.NewTLVBE(wire.ODirTLVNickName, user.AIMDirectoryInfo.NickName))
		reply.Append(wire.NewTLVBE(wire.ODirTLVZIP, user.AIMDirectoryInfo.ZIPCode))
		reply.Append(wire.NewTLVBE(wire.ODirTLVAddress, user.AIMDirectoryInfo.Address))
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateGetDirReply,
			RequestID: inFrame.RequestID,
		},
		Body: reply,
	}, nil
}
