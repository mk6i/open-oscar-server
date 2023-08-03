package oscar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

const (
	ErrorCodeInvalidSnac          = 0x01
	ErrorCodeRateToHost           = 0x02
	ErrorCodeRateToClient         = 0x03
	ErrorCodeNotLoggedOn          = 0x04
	ErrorCodeServiceUnavailable   = 0x05
	ErrorCodeServiceNotDefined    = 0x06
	ErrorCodeObsoleteSnac         = 0x07
	ErrorCodeNotSupportedByHost   = 0x08
	ErrorCodeNotSupportedByClient = 0x09
	ErrorCodeRefusedByClient      = 0x0A
	ErrorCodeReplyTooBig          = 0x0B
	ErrorCodeResponsesLost        = 0x0C
	ErrorCodeRequestDenied        = 0x0D
	ErrorCodeBustedSnacPayload    = 0x0E
	ErrorCodeInsufficientRights   = 0x0F
	ErrorCodeInLocalPermitDeny    = 0x10
	ErrorCodeTooEvilSender        = 0x11
	ErrorCodeTooEvilReceiver      = 0x12
	ErrorCodeUserTempUnavail      = 0x13
	ErrorCodeNoMatch              = 0x14
	ErrorCodeListOverflow         = 0x15
	ErrorCodeRequestAmbigous      = 0x16
	ErrorCodeQueueFull            = 0x17
	ErrorCodeNotWhileOnAol        = 0x18
	ErrorCodeQueryFail            = 0x19
	ErrorCodeTimeout              = 0x1A
	ErrorCodeErrorText            = 0x1B
	ErrorCodeGeneralFailure       = 0x1C
	ErrorCodeProgress             = 0x1D
	ErrorCodeInFreeArea           = 0x1E
	ErrorCodeRestrictedByPc       = 0x1F
	ErrorCodeRemoteRestrictedByPc = 0x20
)

const (
	ErrorTagsFailUrl        = 0x04
	ErrorTagsErrorSubcode   = 0x08
	ErrorTagsErrorText      = 0x1B
	ErrorTagsErrorInfoClsid = 0x29
	ErrorTagsErrorInfoData  = 0x2A
)

type snacError struct {
	code uint16
	TLVPayload
}

func (s *snacError) write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, s.code); err != nil {
		return err
	}
	return s.TLVPayload.write(w)
}

type flapFrame struct {
	startMarker   uint8
	frameType     uint8
	sequence      uint16
	payloadLength uint16
}

const (
	TLV_SCREEN_NAME = 0x01
)

func (f *flapFrame) write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, f.startMarker); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.frameType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.sequence); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, f.payloadLength)
}

func (f *flapFrame) read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &f.startMarker); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &f.frameType); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &f.sequence); err != nil {
		return err
	}
	return binary.Read(r, binary.BigEndian, &f.payloadLength)
}

type snacFrame struct {
	foodGroup uint16
	subGroup  uint16
	flags     uint16
	requestID uint32
}

func (s *snacFrame) write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, s.foodGroup); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, s.subGroup); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, s.flags); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, s.requestID); err != nil {
		return err
	}
	return nil
}

func (s *snacFrame) read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &s.foodGroup); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.subGroup); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.flags); err != nil {
		return err
	}
	return binary.Read(r, binary.BigEndian, &s.requestID)
}

type snacWriter interface {
	write(w io.Writer) error
}

type TLVPayload struct {
	TLVs []*TLV
}

func (s *TLVPayload) read(r io.Reader, lookup map[uint16]reflect.Kind) error {
	for {
		// todo, don't like this extra alloc when we're EOF
		tlv := &TLV{}
		if err := tlv.read(r, lookup); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		s.TLVs = append(s.TLVs, tlv)
	}

	return nil
}

func (s *TLVPayload) write(w io.Writer) error {
	for _, tlv := range s.TLVs {
		if err := tlv.write(w); err != nil {
			return err
		}
	}
	return nil
}

func (s *TLVPayload) getString(tType uint16) (string, bool) {
	for _, tlv := range s.TLVs {
		if tType == tlv.tType {
			return tlv.val.(string), true
		}
	}
	return "", false
}

func (s *TLVPayload) getTLV(tType uint16) (*TLV, bool) {
	for _, tlv := range s.TLVs {
		if tType == tlv.tType {
			return tlv, true
		}
	}
	return nil, false
}

func (s *TLVPayload) getSlice(tType uint16) ([]byte, bool) {
	for _, tlv := range s.TLVs {
		if tType == tlv.tType {
			return tlv.val.([]byte), true
		}
	}
	return nil, false
}

type TLV struct {
	tType uint16
	val   any
}

type snacFrameTLV struct {
	snacFrame
	TLVs []*TLV
}

func (s *snacFrameTLV) write(w io.Writer) error {
	if err := s.snacFrame.write(w); err != nil {
		return err
	}
	for _, tlv := range s.TLVs {
		if err := tlv.write(w); err != nil {
			return err
		}
	}
	return nil
}

func (t *TLV) write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, t.tType); err != nil {
		return err
	}

	var valLen uint16
	val := t.val

	switch t.val.(type) {
	case uint8:
		valLen = 1
	case uint16:
		valLen = 2
	case uint32:
		valLen = 4
	case []uint16:
		valLen = uint16(len(t.val.([]uint16)) * 2)
	case []byte:
		valLen = uint16(len(t.val.([]byte)))
	case string:
		valLen = uint16(len(t.val.(string)))
		val = []byte(t.val.(string))
	case *messageData:
		buf := &bytes.Buffer{}
		if err := t.val.(*messageData).write(buf); err != nil {
			return err
		}
		valLen = uint16(buf.Len())
		val = buf.Bytes()
	}

	if err := binary.Write(w, binary.BigEndian, valLen); err != nil {
		return err
	}

	return binary.Write(w, binary.BigEndian, val)
}

func (t *TLV) read(r io.Reader, typeLookup map[uint16]reflect.Kind) error {
	if err := binary.Read(r, binary.BigEndian, &t.tType); err != nil {
		return err
	}
	var tlvValLen uint16
	if err := binary.Read(r, binary.BigEndian, &tlvValLen); err != nil {
		return err
	}

	kind, ok := typeLookup[t.tType]
	if !ok {
		return fmt.Errorf("unknown data type for TLV %d", t.tType)
	}

	switch kind {
	case reflect.Uint8:
		var val uint16
		if err := binary.Read(r, binary.BigEndian, &val); err != nil {
			return err
		}
		t.val = val
	case reflect.Uint16:
		var val uint16
		if err := binary.Read(r, binary.BigEndian, &val); err != nil {
			return err
		}
		t.val = val
	case reflect.Uint32:
		var val uint32
		if err := binary.Read(r, binary.BigEndian, &val); err != nil {
			return err
		}
		t.val = val
	case reflect.String:
		buf := make([]byte, tlvValLen)
		if _, err := r.Read(buf); err != nil {
			return err
		}
		t.val = string(buf)
	case reflect.Slice:
		buf := make([]byte, tlvValLen)
		if _, err := r.Read(buf); err != nil {
			return err
		}
		t.val = buf
	default:
		panic("unsupported data type")
	}

	return nil
}

type flapSignonFrame struct {
	flapFrame
	flapVersion uint32
	TLVPayload
}

func (f *flapSignonFrame) write(w io.Writer) error {
	if err := f.flapFrame.write(w); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, f.flapVersion)
}

func (f *flapSignonFrame) read(r io.Reader) error {
	if err := f.flapFrame.read(r); err != nil {
		return err
	}

	// todo: combine b+buf?
	b := make([]byte, f.payloadLength)
	if _, err := r.Read(b); err != nil {
		return err
	}

	buf := bytes.NewBuffer(b)
	if err := binary.Read(buf, binary.BigEndian, &f.flapVersion); err != nil {
		return err
	}

	lookup := map[uint16]reflect.Kind{
		0x06: reflect.String,
		0x4A: reflect.Uint8,
	}

	for {
		// todo, don't like this extra alloc when we're EOF
		tlv := &TLV{}
		if err := tlv.read(buf, lookup); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		f.TLVs = append(f.TLVs, tlv)
	}

	return nil
}

func SendAndReceiveSignonFrame(rw io.ReadWriter, sequence *uint32) (*flapSignonFrame, error) {
	flap := &flapSignonFrame{
		flapFrame: flapFrame{
			startMarker:   42,
			frameType:     1,
			sequence:      uint16(*sequence),
			payloadLength: 4, // size of flapVersion
		},
		flapVersion: 1,
	}

	*sequence++

	if err := flap.write(rw); err != nil {
		return nil, err
	}

	fmt.Printf("SendAndReceiveSignonFrame read FLAP: %+v\n", flap)

	// receive
	flap = &flapSignonFrame{}
	if err := flap.read(rw); err != nil {
		return nil, err
	}

	fmt.Printf("SendAndReceiveSignonFrame write FLAP: %+v\n", flap)

	return flap, nil
}

func VerifyLogin(sm *SessionManager, rw io.ReadWriter, sequence *uint32) (*Session, error) {
	flap, err := SendAndReceiveSignonFrame(rw, sequence)
	if err != nil {
		return nil, err
	}

	var ok bool
	ID, ok := flap.getString(OserviceTlvTagsLoginCookie)
	if !ok {
		return nil, errors.New("unable to get session ID from payload")
	}

	sess, ok := sm.Retrieve(ID)
	if !ok {
		return nil, fmt.Errorf("unable to find session by ID %s", ID)
	}

	return sess, nil
}

const (
	OSERVICE      uint16 = 0x0001
	LOCATE               = 0x0002
	BUDDY                = 0x0003
	ICBM                 = 0x0004
	ADVERT               = 0x0005
	INVITE               = 0x0006
	ADMIN                = 0x0007
	POPUP                = 0x0008
	PD                   = 0x0009
	USER_LOOKUP          = 0x000A
	STATS                = 0x000B
	TRANSLATE            = 0x000C
	CHAT_NAV             = 0x000D
	CHAT                 = 0x000E
	ODIR                 = 0x000F
	BART                 = 0x0010
	FEEDBAG              = 0x0013
	ICQ                  = 0x0015
	BUCP                 = 0x0017
	ALERT                = 0x0018
	PLUGIN               = 0x0022
	UNNAMED_FG_24        = 0x0024
	MDIR                 = 0x0025
	ARS                  = 0x044A
)

type IncomingMessage struct {
	flap *flapFrame
	snac *snacFrame
	buf  io.Reader
}

type XMessage struct {
	// todo: this should only take values, not pointers, in order to avoid race
	// conditions
	flap      *flapFrame
	snacFrame snacFrame
	snacOut   snacWriter
}

func streamFromConn(rw io.ReadWriter, in chan IncomingMessage) {
	for {
		flap := &flapFrame{}
		if err := flap.read(rw); err != nil {
			if err != io.EOF {
				panic("temporary panic: " + err.Error())
			} else {
				break
			}
		}

		b := make([]byte, flap.payloadLength)
		if _, err := rw.Read(b); err != nil {
			if err != io.EOF {
				panic("temporary panic: " + err.Error())
			} else {
				break
			}
		}

		buf := bytes.NewBuffer(b)

		snac := &snacFrame{}
		if err := snac.read(buf); err != nil {
			if err != io.EOF {
				panic("temporary panic: " + err.Error())
			} else {
				break
			}
		}

		in <- IncomingMessage{
			flap: flap,
			snac: snac,
			buf:  buf,
		}
	}
}

func ReadBos(sm *SessionManager, sess *Session, fm *FeedbagStore, rw io.ReadWriter, sequence *uint32) error {
	in := make(chan IncomingMessage)
	defer close(in)

	go streamFromConn(rw, in)

	for {
		select {
		case m := <-in:
			err := routeIncomingRequests(sm, sess, fm, rw, sequence, m.snac, m.flap, m.buf)
			if err != nil {
				return err
			}
		case m := <-sess.MsgChan:
			if err := writeOutSNAC(nil, m.flap, m.snacFrame, m.snacOut, sequence, rw); err != nil {
				panic("error handling handleXMessage: " + err.Error())
			}
		}
	}
}

func routeIncomingRequests(sm *SessionManager, sess *Session, fm *FeedbagStore, rw io.ReadWriter, sequence *uint32, snac *snacFrame, flap *flapFrame, buf io.Reader) error {
	switch snac.foodGroup {
	case OSERVICE:
		if err := routeOService(sm, fm, sess, flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case LOCATE:
		if err := routeLocate(sess, sm, fm, flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case BUDDY:
		if err := routeBuddy(flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case ICBM:
		if err := routeICBM(sm, fm, sess, flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case PD:
		if err := routePD(flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case CHAT_NAV:
		if err := routeChatNav(flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case FEEDBAG:
		if err := routeFeedbag(sm, sess, fm, flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	case BUCP:
		if err := routeBUCP(flap, snac, buf, rw, sequence); err != nil {
			return err
		}
	default:
		panic(fmt.Sprintf("unsupported food group: %d", snac.foodGroup))
	}

	return nil
}

func writeOutSNAC(originSnac *snacFrame, flap *flapFrame, snacFrame snacFrame, snacOut snacWriter, sequence *uint32, w io.Writer) error {
	if originSnac != nil {
		snacFrame.requestID = originSnac.requestID
	}

	snacBuf := &bytes.Buffer{}
	if err := snacFrame.write(snacBuf); err != nil {
		return err
	}
	if err := snacOut.write(snacBuf); err != nil {
		return err
	}

	flap.sequence = uint16(*sequence)
	*sequence++
	flap.payloadLength = uint16(snacBuf.Len())

	fmt.Printf(" write FLAP: %+v\n", flap)

	if err := flap.write(w); err != nil {
		return err
	}

	fmt.Printf(" write SNAC: %+v\n", snacOut)

	expectLen := snacBuf.Len()
	c, err := w.Write(snacBuf.Bytes())

	if c != expectLen {
		panic("did not write the expected # of bytes")
	}
	return err
}
