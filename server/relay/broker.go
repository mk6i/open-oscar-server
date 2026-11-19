package relay

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// relayedCaps lists the services the server relays. Everything else, such as
// room invites and voice, is passed on as usual.
var relayedCaps = []uuid.UUID{wire.CapDirectICBM, wire.CapFileTransfer, wire.CapFileSharing}

// BrokerRendezvous points a direct offer at the server, so neither client
// needs to reach the other. It implements foodgroup.RendezvousBroker.
func (s *Server) BrokerRendezvous(instance *state.SessionInstance, recipient state.IdentScreenName, frag wire.ICBMCh2Fragment) (wire.ICBMCh2Fragment, bool) {
	if frag.Type == wire.ICBMRdvMessageCancel {
		s.registry.cancel(frag.Cookie)
		return frag, false
	}
	if frag.Type != wire.ICBMRdvMessagePropose || !slices.Contains(relayedCaps, uuid.UUID(frag.Capability)) || frag.HasTag(wire.ICBMRdvTLVTagsUseARS) {
		return frag, false
	}
	if seq, ok := frag.Uint16BE(wire.ICBMRdvTLVTagsSeqNum); !ok || seq != 1 {
		return frag, false
	}

	sess := &session{
		cookie:       frag.Cookie,
		offerer:      instance,
		offererIP:    instanceIP(instance),
		recipient:    recipient,
		recipientIPs: s.instanceIPs(recipient),
		capability:   frag.Capability,
	}
	if !s.registry.reserve(sess, s.acceptTimeout) {
		return frag, false
	}
	tagsIn := tagList(frag)
	s.setAddress(&frag)
	s.logger.Info("relaying rendezvous",
		"offerer", instance.IdentScreenName().String(),
		"recipient", recipient.String(),
		"cap", uuid.UUID(frag.Capability).String(),
		"cookie", fmt.Sprintf("%x", frag.Cookie),
		"tags_in", tagsIn,
		"tags_out", tagList(frag))
	return frag, true
}

// HoldRendezvous keeps back the recipient's accept. It only says the
// recipient reached the server, and the offerer has a counter-offer to follow.
// It implements foodgroup.RendezvousBroker.
func (s *Server) HoldRendezvous(instance *state.SessionInstance, frag wire.ICBMCh2Fragment) bool {
	if frag.Type != wire.ICBMRdvMessageAccept {
		return false
	}
	sess, err := s.registry.lookup(frag.Cookie)
	if err != nil || instance.IdentScreenName() != sess.recipient {
		return false
	}
	sess.markAccepted()
	s.logger.Info("held rendezvous accept", "cookie", fmt.Sprintf("%x", frag.Cookie))
	return true
}

// RefuseRendezvous ends a session the recipient turned down. AIM declines with
// a client error, not a rendezvous cancel. It implements
// foodgroup.RendezvousBroker.
func (s *Server) RefuseRendezvous(cookie uint64) {
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], cookie)
	if s.registry.cancel(id) {
		s.logger.Info("rendezvous refused", "cookie", fmt.Sprintf("%x", id))
	}
}

// setAddress writes the server's address into a rendezvous offer.
func (s *Server) setAddress(frag *wire.ICBMCh2Fragment) {
	ip := s.advertisedIP.As4()
	frag.Remove(wire.ICBMRdvTLVTagsRdvIP)
	frag.Remove(wire.ICBMRdvTLVTagsIPXOR)
	frag.Remove(wire.ICBMRdvTLVTagsPortXOR)
	frag.Set(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, ip[:]))
	frag.Set(wire.NewTLVBE(wire.ICBMRdvTLVTagsVerifiedIP, ip[:]))
	frag.Set(wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, s.advertisedPort))
}

// counterOffer tells the offerer to dial the server too. To the offerer it
// reads as the recipient asking it to connect instead.
func (s *Server) counterOffer(sess *session, logger *slog.Logger) {
	recipient := s.sessionRetriever.RetrieveSession(sess.recipient)
	if recipient == nil {
		logger.Info("recipient signed off before the counter-offer")
		return
	}

	frag := wire.ICBMCh2Fragment{
		Type:       wire.ICBMRdvMessagePropose,
		Cookie:     sess.cookie,
		Capability: sess.capability,
	}
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(2)))
	s.setAddress(&frag)

	msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		Cookie:      binary.BigEndian.Uint64(sess.cookie[:]),
		ChannelID:   wire.ICBMChannelRendezvous,
		TLVUserInfo: recipient.TLVUserInfo(),
	}
	msg.Append(wire.NewTLVBE(wire.ICBMTLVData, frag))

	status := sess.offerer.RelayMessageToInstance(wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
			RequestID: wire.ReqIDFromServer,
		},
		Body: msg,
	})
	logger.Info("sent counter-offer", "offerer", sess.offerer.IdentScreenName().String(), "status", status)
}

func (s *Server) instanceIPs(screenName state.IdentScreenName) []netip.Addr {
	session := s.sessionRetriever.RetrieveSession(screenName)
	if session == nil {
		return nil
	}
	var ips []netip.Addr
	for _, instance := range session.Instances() {
		ips = append(ips, instanceIP(instance))
	}
	return ips
}

func instanceIP(instance *state.SessionInstance) netip.Addr {
	if addr := instance.RemoteAddr(); addr != nil {
		return addr.Addr().Unmap()
	}
	return netip.Addr{}
}

// tagList names a rendezvous message's fields, in the order they were sent.
func tagList(frag wire.ICBMCh2Fragment) string {
	tags := make([]string, 0, len(frag.TLVList))
	for _, tlv := range frag.TLVList {
		tags = append(tags, fmt.Sprintf("%04x", tlv.Tag))
	}
	return strings.Join(tags, " ")
}
