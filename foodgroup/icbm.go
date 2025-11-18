package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

const (
	evilDelta         = uint16(100)
	evilDeltaAnon     = uint16(30)
	warningDecayPct   = -50
	rateDecayInterval = 5 * time.Minute
)

// NewICBMService returns a new instance of ICBMService.
func NewICBMService(
	bartItemManager BARTItemManager,
	messageRelayer MessageRelayer,
	offlineMessageSaver OfflineMessageManager,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	userManager UserManager,
	feedbagManager FeedbagManager,
	snacRateLimits wire.SNACRateLimits,
	logger *slog.Logger,
) *ICBMService {
	return &ICBMService{
		relationshipFetcher:   relationshipFetcher,
		buddyBroadcaster:      newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:        messageRelayer,
		offlineMessageSaver:   offlineMessageSaver,
		offlineMessageManager: offlineMessageSaver,
		userManager:           userManager,
		feedbagManager:        feedbagManager,
		timeNow:               time.Now,
		sessionRetriever:      sessionRetriever,
		snacRateLimits:        snacRateLimits,
		convoTracker:          newConvoTracker(),
		logger:                logger,
		interval:              rateDecayInterval,
	}
}

// ICBMService provides functionality for the ICBM food group, which is
// responsible for sending and receiving instant messages and associated
// functionality such as warning, typing events, etc.
type ICBMService struct {
	relationshipFetcher   RelationshipFetcher
	buddyBroadcaster      buddyBroadcaster
	messageRelayer        MessageRelayer
	offlineMessageSaver   OfflineMessageManager
	userManager           UserManager
	feedbagManager        FeedbagManager
	timeNow               func() time.Time
	sessionRetriever      SessionRetriever
	snacRateLimits        wire.SNACRateLimits
	convoTracker          *convoTracker
	logger                *slog.Logger
	interval              time.Duration
	offlineMessageManager OfflineMessageManager
}

// ParameterQuery returns ICBM service parameters.
func (s ICBMService) ParameterQuery(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMParameterReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x05_ICBMParameterReply{
			MaxSlots:             100,
			ICBMFlags:            3,
			MaxIncomingICBMLen:   512,
			MaxSourceEvil:        999,
			MaxDestinationEvil:   999,
			MinInterICBMInterval: 0,
		},
	}
}

// ChannelMsgToHost relays the instant message SNAC wire.ICBMChannelMsgToHost
// from the sender to the intended recipient. It returns wire.ICBMHostAck if
// the wire.ICBMChannelMsgToHost message contains a request acknowledgement
// flag.
func (s ICBMService) ChannelMsgToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
	recip := state.NewIdentScreenName(inBody.ScreenName)

	rel, err := s.relationshipFetcher.Relationship(ctx, sess.IdentScreenName(), recip)
	if err != nil {
		return nil, err
	}

	switch {
	case rel.BlocksYou:
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	case rel.YouBlock:
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeInLocalPermitDeny), nil
	}

	recipSess := s.sessionRetriever.RetrieveSession(recip)
	if recipSess == nil {
		// check for TLV that indicates that the message should be saved offline.
		// For AIM 6/7, this is only set if the sender has the recipient on
		// their buddy list and they've seen them online at least once.
		if _, saveOffline := inBody.Bytes(wire.ICBMTLVStore); !saveOffline {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		canSend, err := s.canSendOfflineMessage(ctx, inBody)
		if err != nil {
			return nil, err
		}
		if !canSend {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		msg, err := s.sendOfflineMessage(ctx, sess, inFrame, inBody)
		if errors.Is(err, state.ErrNoUser) {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		return msg, err
	}

	clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		Cookie:       inBody.Cookie,
		ChannelID:    inBody.ChannelID,
		TLVUserInfo:  sess.TLVUserInfo(),
		TLVRestBlock: wire.TLVRestBlock{},
	}

	for _, tlv := range inBody.TLVRestBlock.TLVList {
		if tlv.Tag == wire.ICBMTLVRequestHostAck {
			// Exclude this TLV, because its presence breaks chat invitations
			// on macOS client v4.0.9.
			continue
		}
		if clientIM.ChannelID == wire.ICBMChannelRendezvous && tlv.Tag == wire.ICBMTLVData {
			if tlv, err = addExternalIP(sess, tlv); err != nil {
				return nil, fmt.Errorf("addExternalIP: %w", err)
			}
		}
		clientIM.Append(tlv)
	}

	if sess.TypingEventsEnabled() && (inBody.ChannelID == wire.ICBMChannelIM || inBody.ChannelID == wire.ICBMChannelMIME) {
		// tell the receiver that we want to receive their typing events
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVWantEvents, []byte{}))
	}

	s.messageRelayer.RelayToScreenName(ctx, recipSess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
			RequestID: wire.ReqIDFromServer,
		},
		Body: clientIM,
	})

	s.convoTracker.trackConvo(time.Now(), sess.IdentScreenName(), recipSess.IdentScreenName())

	if _, requestedConfirmation := inBody.TLVRestBlock.Bytes(wire.ICBMTLVRequestHostAck); !requestedConfirmation {
		// don't ack message
		return nil, nil
	}

	// ack message back to sender
	return &wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMHostAck,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
			Cookie:     inBody.Cookie,
			ChannelID:  inBody.ChannelID,
			ScreenName: inBody.ScreenName,
		},
	}, nil
}

// canSendOfflineMessage returns true if the user can send an offline message.
//
//	For ICQ users, always return true. Todo: Check ICQ recipient's preferences.
//
//	For AIM users, only return false if the recipient has specifically opted out
//	of receiving offline messages or they do not have a stored buddy list.
func (s ICBMService) canSendOfflineMessage(ctx context.Context, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (bool, error) {
	bag, err := s.feedbagManager.Feedbag(ctx, state.NewIdentScreenName(inBody.ScreenName))
	if err != nil {
		return false, fmt.Errorf("get feedbag failed: %w", err)
	}

	for _, item := range bag {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs {
			valid, ok := feedbagBuddyPref(wire.FeedbagBuddyPrefsAcceptOfflineIM, item.TLVList)
			return !valid || ok, nil
		}
	}

	return true, nil
}

func (s ICBMService) sendOfflineMessage(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
	recip := state.NewIdentScreenName(inBody.ScreenName)

	offlineMsg := state.OfflineMessage{
		Message:   inBody,
		Recipient: recip,
		Sender:    sess.IdentScreenName(),
		Sent:      s.timeNow().UTC(),
	}
	if _, err := s.offlineMessageSaver.SaveMessage(ctx, offlineMsg); err != nil {
		if errors.Is(err, state.ErrOfflineInboxFull) {
			return newICBMErr(
				inFrame.RequestID,
				wire.ErrorCodeNotLoggedOn,
				wire.NewTLVBE(wire.ErrorTLVErrorSubcode, wire.ICBMSubErrOfflineIMExceedMax),
			), nil
		}
		return nil, fmt.Errorf("save ICBM offline message failed: %w", err)
	}

	if sess.UIN() > 0 {
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	}

	if _, requestedConfirmation := inBody.TLVRestBlock.Bytes(wire.ICBMTLVRequestHostAck); requestedConfirmation {
		// ack message back to sender
		return &wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMHostAck,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
				Cookie:     inBody.Cookie,
				ChannelID:  inBody.ChannelID,
				ScreenName: inBody.ScreenName,
			},
		}, nil
	}
	return nil, nil
}

// addExternalIP appends the client's IP address to the TLV if it's an ICBM
// rendezvous proposal/accept message.
func addExternalIP(sess *state.Session, tlv wire.TLV) (wire.TLV, error) {
	frag := wire.ICBMCh2Fragment{}
	if err := wire.UnmarshalBE(&frag, bytes.NewReader(tlv.Value)); err != nil {
		return tlv, fmt.Errorf("wire.UnmarshalBE: %w", err)
	}
	if frag.Type != wire.ICBMRdvMessagePropose {
		return tlv, nil
	}
	if frag.HasTag(wire.ICBMRdvTLVTagsRequesterIP) && sess.RemoteAddr() != nil && sess.RemoteAddr().Addr().Is4() {
		ip := sess.RemoteAddr().Addr()
		// replace the IP set by the client with the actual IP seen by the
		// server. unlike AOL’s original behavior, this allows NATed clients
		// to use rendezvous by replacing their LAN IP with the correct
		// external IP.
		frag.Replace(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, ip.AsSlice()))
		// append the client’s IP as seen by the server. the recipient uses
		// this to verify that the sender’s claimed IP matches what the server
		// detects. although redundant since we override the requester IP
		// above, it remains required for client compatibility.
		frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsVerifiedIP, ip.AsSlice()))
		return wire.NewTLVBE(tlv.Tag, frag), nil
	}

	return tlv, nil
}

// ClientEvent relays SNAC wire.ICBMClientEvent typing events from the
// sender to the recipient.
func (s ICBMService) ClientEvent(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error {
	blocked, err := s.relationshipFetcher.Relationship(ctx, sess.IdentScreenName(), state.NewIdentScreenName(inBody.ScreenName))

	switch {
	case err != nil:
		return err
	case blocked.BlocksYou || blocked.YouBlock:
		return nil
	default:
		recipient := state.NewIdentScreenName(inBody.ScreenName)
		s.messageRelayer.RelayToScreenName(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMClientEvent,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
				Cookie:     inBody.Cookie,
				ChannelID:  inBody.ChannelID,
				ScreenName: string(sess.DisplayScreenName()),
				Event:      inBody.Event,
			},
		})

		return nil
	}
}

func (s ICBMService) ClientErr(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x0B_ICBMClientErr) error {
	s.messageRelayer.RelayToScreenName(ctx, state.NewIdentScreenName(inBody.ScreenName), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMClientErr,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x0B_ICBMClientErr{
			Cookie:     inBody.Cookie,
			ChannelID:  inBody.ChannelID,
			ScreenName: sess.DisplayScreenName().String(),
			Code:       inBody.Code,
			ErrInfo:    inBody.ErrInfo,
		},
	})
	return nil
}

// EvilRequest handles user warning (a.k.a evil) notifications. It receives
// wire.ICBMEvilRequest warning SNAC, increments the warned user's warning
// level, and sends the warned user a notification informing them that they
// have been warned. The user may choose to warn anonymously or
// non-anonymously. It returns SNAC wire.ICBMEvilReply to confirm that the
// warning was sent. Users may not warn themselves or warn users they have
// blocked or are blocked by.
func (s ICBMService) EvilRequest(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x08_ICBMEvilRequest) (wire.SNACMessage, error) {
	identScreenName := state.NewIdentScreenName(inBody.ScreenName)

	// don't let users warn themselves, it causes the AIM client to go into a
	// weird state.
	if identScreenName == sess.IdentScreenName() {
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotSupportedByHost), nil
	}

	blocked, err := s.relationshipFetcher.Relationship(ctx, sess.IdentScreenName(), identScreenName)
	if err != nil {
		return wire.SNACMessage{}, err
	}
	if blocked.BlocksYou || blocked.YouBlock {
		// user or target is blocked
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	}

	recipSess := s.sessionRetriever.RetrieveSession(identScreenName)
	if recipSess == nil {
		// target user is offline
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	}

	if recipSess.UserInfoBitmask()&wire.OServiceUserFlagBot == wire.OServiceUserFlagBot {
		// target user is a bot, bots can't be warned
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	canWarn := s.convoTracker.trackWarn(time.Now(), sess.IdentScreenName(), recipSess.IdentScreenName())
	if !canWarn {
		// user has warned target too many times or not enough messages have
		// been received from target
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	increase := evilDelta
	if inBody.SendAs == 1 {
		increase = evilDeltaAnon
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	ok, newLevel := recipSess.ScaleWarningAndRateLimit(int16(increase), classID)
	if !ok {
		// target's warning is at 100%
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	notif := wire.SNAC_0x01_0x10_OServiceEvilNotification{
		NewEvil: newLevel,
	}

	// append info about user who sent the warning
	if inBody.SendAs == 0 {
		notif.Snitcher = &struct {
			wire.TLVUserInfo
		}{
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName:   sess.DisplayScreenName().String(),
				WarningLevel: sess.Warning(),
			},
		}
	}

	s.messageRelayer.RelayToScreenName(ctx, recipSess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceEvilNotification,
		},
		Body: notif,
	})

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMEvilReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x09_ICBMEvilReply{
			EvilDeltaApplied: increase,
			UpdatedEvilValue: newLevel,
		},
	}, nil
}

func (s ICBMService) OfflineRetrieve(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame) (wire.SNACMessage, error) {
	msgList, err := s.offlineMessageManager.RetrieveMessages(ctx, sess.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("retrieving messages: %w", err)
	}

	for _, event := range msgList {
		clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			Cookie:    event.Message.Cookie,
			ChannelID: event.Message.ChannelID,
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: event.Sender.String(),
			},
			TLVRestBlock: wire.TLVRestBlock{},
		}

		for _, tlv := range event.Message.TLVRestBlock.TLVList {
			clientIM.Append(tlv)
		}
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(event.Sent.Unix())))

		s.messageRelayer.RelayToScreenName(ctx, event.Recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: clientIM,
		})
	}

	if len(msgList) > 0 {
		if err := s.offlineMessageManager.DeleteMessages(ctx, sess.IdentScreenName()); err != nil {
			return wire.SNACMessage{}, fmt.Errorf("offlineMessageManager.DeleteMessages: %w", err)
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMOfflineRetrieveReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply{},
	}, nil
}

// RestoreWarningLevel restores the warning level from the last stored value at login time,
// accounting for time passed between logins.
func (s ICBMService) RestoreWarningLevel(ctx context.Context, sess *state.Session) error {
	u, err := s.userManager.User(ctx, sess.IdentScreenName())
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if u == nil {
		return state.ErrNoUser
	}

	if u.LastWarnLevel == 0 {
		// user had no warning at the end of last session
		return nil
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	// increment warning level by the amount of time that has passed since last
	// login, proportionally increasing the warning level
	warnDelta := calcElapsedWarningLevel(u.LastWarnUpdate, s.timeNow(), s.interval)
	newWarning := int16(u.LastWarnLevel) + warnDelta
	sess.SetWarning(0)
	sess.ScaleWarningAndRateLimit(newWarning, classID)

	if sess.Warning() > 0 {
		s.logger.DebugContext(ctx, "restored warning level with time decay applied since last login",
			"stored_level", u.LastWarnLevel,
			"time_since_update", s.timeNow().Sub(u.LastWarnUpdate),
			"decay_delta", warnDelta,
			"final_level", sess.Warning(),
		)
	} else {
		s.logger.DebugContext(ctx, "warning level decayed to zero since last login",
			"stored_level", u.LastWarnLevel,
			"time_since_update", s.timeNow().Sub(u.LastWarnUpdate),
			"decay_delta", warnDelta,
		)
	}

	return nil
}

// UpdateWarnLevel periodically updates the warning level relative to time
// elapsed between warnings.
func (s ICBMService) UpdateWarnLevel(ctx context.Context, sess *state.Session) {
	var inProgress bool
	var ticker *time.Ticker
	var tickC <-chan time.Time // nil when idle, enables/disables the select case
	var doReset bool

	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
		tickC = nil
		inProgress = false
		s.logger.DebugContext(ctx, "warning decay stopped")
	}

	startTicker := func(interval time.Duration) {
		ticker = time.NewTicker(interval)
		tickC = ticker.C
		inProgress = true
		s.logger.DebugContext(ctx, "warning decay started")
	}

	if sess.Warning() > 0 {
		u, err := s.userManager.User(ctx, sess.IdentScreenName())
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to get user", "err", err)
			return
		}
		newInterval := timeTillNextInterval(u.LastWarnUpdate, s.timeNow(), s.interval)
		interval := s.interval
		if newInterval > 0 {
			interval = newInterval
		}
		s.logger.DebugContext(ctx, "starting warning level update with interval adjusted to next boundary",
			"user", sess.IdentScreenName(),
			"adjusted_interval", interval,
			"default_interval", s.interval,
			"time_since_last_update", s.timeNow().Sub(u.LastWarnUpdate),
		)
		startTicker(interval)
		doReset = true
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	warnCh := make(chan struct{}, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(warnCh)
		for {
			select {
			case <-sess.Closed():
				return
			case <-ctx.Done():
				return
			case warning := <-sess.WarningCh():
				if warning > 0 {
					warnCh <- struct{}{}
				}
				if err := s.userManager.SetWarnLevel(ctx, sess.IdentScreenName(), s.timeNow(), warning); err != nil {
					s.logger.ErrorContext(ctx, "failed to set warn level", "err", err)
				}

				info := sess.TLVUserInfo()
				// lock in the current warning level to avoid race conditions
				// where the warning level might change during this broadcast
				// operation
				info.WarningLevel = warning
				if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, sess.IdentScreenName(), info); err != nil {
					s.logger.ErrorContext(ctx, "BroadcastBuddyArrived failed", "err", err)
				} else {
					s.logger.DebugContext(ctx, "warning lowered", "remaining", warning)
				}
			}
		}
	}()

	defer wg.Wait()

	for {
		select {
		case <-sess.Closed():
			stopTicker()
			return
		case <-ctx.Done():
			stopTicker()
			return

		case <-warnCh:
			if inProgress {
				s.logger.DebugContext(ctx, "warning decay already in progress")
				continue
			}
			startTicker(s.interval)

		case <-tickC:
			if doReset {
				ticker.Reset(s.interval)
				doReset = false
			}

			ok, warning := sess.ScaleWarningAndRateLimit(warningDecayPct, classID)
			if !ok {
				s.logger.ErrorContext(ctx, "warning increment out of rage", "level", warning)
				stopTicker()
				return
			}

			if warning == 0 {
				s.logger.DebugContext(ctx, "warning decay complete")
				stopTicker()
			}
		}
	}
}

func newICBMErr(requestID uint32, errCode uint16, tlvs ...wire.TLV) *wire.SNACMessage {
	body := wire.SNACError{
		Code: errCode,
	}
	if len(tlvs) > 0 {
		body.AppendList(tlvs)
	}
	return &wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMErr,
			RequestID: requestID,
		},
		Body: body,
	}
}

func calcElapsedWarningLevel(lastWarnUpdate time.Time, now time.Time, interval time.Duration) int16 {
	// time passed since last signoff
	since := now.Sub(lastWarnUpdate)

	// how many times warning decayed since last signoff
	decayPeriods := int(since / interval)
	// total amount warning decreased since last signoff
	warnDelta := decayPeriods * warningDecayPct

	return int16(warnDelta)
}

func timeTillNextInterval(lastWarned time.Time, now time.Time, interval time.Duration) time.Duration {
	return interval - (now.Sub(lastWarned) % interval)
}

// convoTracker keeps track of messages initiated from a sender to a recipient.
// A user (the warner) can only warn another user (the warnee) only if the
// warner has received a message from the warnee. The warner may only warn 1
// time per message received from warnee. The warner may only warn the warnee
// up to 3 times per warn window.
type convoTracker struct {
	convos *cache.Cache
	warns  *cache.Cache
	window time.Duration
}

func newConvoTracker() *convoTracker {
	window := 1 * time.Hour
	return &convoTracker{
		convos: cache.New(window, window),
		warns:  cache.New(window, window),
		window: window,
	}
}

// trackConvo records a conversation from sender to recipient at the given time.
func (w *convoTracker) trackConvo(now time.Time, sender, recip state.IdentScreenName) {
	k := w.key(sender, recip)

	buf, found := w.convos.Get(k)
	if !found {
		buf = &ringBuffer{}
		w.convos.Set(k, buf, time.Hour)
	}

	buf.(*ringBuffer).set(now)
}

// trackWarn attempts to record a warning from warner to warnee.
// It returns true if the warning is allowed (warnee has sent more messages
// than warnings in the current window), or false if the warning limit has been
// reached or no conversation exists in the current window.
func (w *convoTracker) trackWarn(now time.Time, warner, warnee state.IdentScreenName) bool {
	key := w.key(warnee, warner)

	convos, found := w.convos.Get(key)
	if !found {
		// no convos tracked, can't warn
		return false
	}

	windowStart := now.Add(-w.window)

	// get convo count during window
	var convoCt int
	for _, v := range convos.(*ringBuffer).vals {
		if v.After(windowStart) {
			convoCt++
		}
	}

	warns, found := w.warns.Get(key)
	if !found {
		warns = &ringBuffer{}
		w.warns.Set(key, warns, time.Hour)
	}

	// get warn count during window
	var warnCount int
	for _, v := range warns.(*ringBuffer).vals {
		if v.After(windowStart) {
			warnCount++
		}
	}

	if convoCt <= warnCount {
		return false
	}

	warns.(*ringBuffer).set(now)

	return true
}

func (w *convoTracker) key(sender state.IdentScreenName, recip state.IdentScreenName) string {
	return sender.String() + recip.String()
}

// ringBuffer is a fixed-size circular buffer with 3 slots for storing time values.
type ringBuffer struct {
	cur  int          // Current cursor position (0, 1, or 2)
	vals [3]time.Time // Fixed-size array to store time values
}

// val returns the time at the current cursor position.
func (r *ringBuffer) val() time.Time {
	return r.vals[r.cur]
}

// set stores the given time at the current cursor position and advances the cursor.
func (r *ringBuffer) set(v time.Time) {
	r.vals[r.cur] = v
	r.cur = (r.cur + 1) % len(r.vals)
}
