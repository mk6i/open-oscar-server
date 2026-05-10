package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// JimmPayloadAuditResult captures one payload check against the Jimm 0.6.0
// reader model we reconstructed from the binary.
type JimmPayloadAuditResult struct {
	Name       string
	PayloadHex string
	Trace      []string
	Err        error
}

// Jimm060FullInfoPayloadAudit serializes the current foodgroup full-info
// replies and checks whether the resulting payload bytes can be consumed by the
// Jimm 0.6.0 reader model we reconstructed from the jar.
func Jimm060FullInfoPayloadAudit() ([]JimmPayloadAuditResult, error) {
	sess := state.NewSession()
	sess.SetUIN(1559105)
	inst := sess.AddInstance()
	user := sampleJimm060User()

	results := make([]JimmPayloadAuditResult, 0, 5)
	cases := []struct {
		name string
		run  func(*ICQService, context.Context, *state.SessionInstance, state.User, uint16) error
		spec func([]byte) ([]string, error)
	}{
		{"00C8 basic", func(s *ICQService, ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
			return s.userInfo(ctx, instance, user, seq)
		}, traceJimm06000C8},
		{"00DC more", func(s *ICQService, ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
			return s.moreUserInfo(ctx, instance, user, seq)
		}, traceJimm06000DC},
		{"00D2 work", func(s *ICQService, ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
			return s.workInfo(ctx, instance, user, seq)
		}, traceJimm06000D2},
		{"00E6 notes", func(s *ICQService, ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
			return s.notes(ctx, instance, user, seq)
		}, traceJimm06000E6},
		{"00FA affiliations", func(s *ICQService, ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
			return s.affiliations(ctx, instance, user, seq)
		}, traceJimm06000FA},
	}

	for i, tc := range cases {
		capture := &auditMessageRelayer{}
		svc := &ICQService{
			messageRelayer: capture,
			timeNow:        time.Now,
		}

		err := tc.run(svc, context.Background(), inst, user, uint16(48+i))
		if err != nil {
			results = append(results, JimmPayloadAuditResult{
				Name: tc.name,
				Err:  err,
			})
			continue
		}
		if !capture.ok {
			results = append(results, JimmPayloadAuditResult{
				Name: tc.name,
				Err:  fmt.Errorf("message relayer was not called"),
			})
			continue
		}

		envelope, err := extractAuditEnvelope(capture.msg)
		if err != nil {
			results = append(results, JimmPayloadAuditResult{Name: tc.name, Err: err})
			continue
		}

		raw, err := marshalAuditLE(envelope)
		if err != nil {
			results = append(results, JimmPayloadAuditResult{Name: tc.name, Err: err})
			continue
		}

		inner, err := auditUnwrapEnvelope(raw)
		if err != nil {
			results = append(results, JimmPayloadAuditResult{
				Name:       tc.name,
				PayloadHex: hex.EncodeToString(raw),
				Err:        err,
			})
			continue
		}

		trace, err := tc.spec(inner)
		if err != nil {
			results = append(results, JimmPayloadAuditResult{
				Name:       tc.name,
				PayloadHex: hex.EncodeToString(inner),
				Trace:      trace,
				Err:        err,
			})
			continue
		}

		results = append(results, JimmPayloadAuditResult{
			Name:       tc.name,
			PayloadHex: hex.EncodeToString(inner),
			Trace:      trace,
		})
	}

	return results, nil
}

type auditMessageRelayer struct {
	msg wire.SNACMessage
	ok  bool
}

func (c *auditMessageRelayer) RelayToScreenNames(context.Context, []state.IdentScreenName, wire.SNACMessage) {
}
func (c *auditMessageRelayer) RelayToScreenName(_ context.Context, _ state.IdentScreenName, msg wire.SNACMessage) {
	c.msg = msg
	c.ok = true
}
func (c *auditMessageRelayer) RelayToOtherInstances(context.Context, *state.SessionInstance, wire.SNACMessage) {
}
func (c *auditMessageRelayer) RelayToScreenNameActiveOnly(context.Context, state.IdentScreenName, wire.SNACMessage) {
}
func (c *auditMessageRelayer) RelayToSelf(context.Context, *state.SessionInstance, wire.SNACMessage) {
}

func sampleJimm060User() state.User {
	return state.User{
		IdentScreenName: state.NewIdentScreenName("1559105"),
		IsICQ:           true,
		ICQInfo: state.ICQInfo{
			Basic: state.ICQBasicInfo{
				Nickname:     "1559105",
				FirstName:    "1559105",
				LastName:     "",
				EmailAddress: "",
				City:         "",
				State:        "",
				Phone:        "",
				Fax:          "",
				Address:      "",
				CellPhone:    "",
			},
			More: state.ICQMoreInfo{
				Gender:       0,
				HomePageAddr: "",
				BirthYear:    0,
				BirthMonth:   0,
				BirthDay:     0,
				Lang1:        0,
				Lang2:        0,
				Lang3:        0,
			},
			Work: state.ICQWorkInfo{
				City:        "",
				State:       "",
				Phone:       "",
				Fax:         "",
				Address:     "",
				ZIPCode:     "",
				CountryCode: 0,
				Company:     "",
				Department:  "",
				Position:    "",
				WebPage:     "",
			},
			Notes: state.ICQUserNotes{
				Notes: "",
			},
			Affiliations: state.ICQAffiliations{
				PastCount:    0,
				CurrentCount: 0,
			},
		},
	}
}

func extractAuditEnvelope(msg wire.SNACMessage) ([]byte, error) {
	body, ok := msg.Body.(wire.SNAC_0x15_0x02_DBReply)
	if !ok {
		return nil, fmt.Errorf("unexpected SNAC body type: %T", msg.Body)
	}
	if len(body.TLVList) != 1 {
		return nil, fmt.Errorf("expected one metadata TLV, got %d", len(body.TLVList))
	}
	return body.TLVList[0].Value, nil
}

func auditUnwrapEnvelope(raw []byte) ([]byte, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("envelope too short")
	}
	wantLen := binary.LittleEndian.Uint16(raw[:2])
	body := raw[2:]
	if int(wantLen) != len(body) {
		return nil, fmt.Errorf("envelope length=%d want %d", len(body), wantLen)
	}
	return body, nil
}

func marshalAuditLE(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := wire.MarshalLE(v, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func traceJimm06000C8(b []byte) ([]string, error) {
	return tracePacket(b, wire.ICQDBQueryMetaReply, wire.ICQDBQueryMetaReplyBasicInfo, traceC8)
}
func traceJimm06000DC(b []byte) ([]string, error) {
	return tracePacket(b, wire.ICQDBQueryMetaReply, wire.ICQDBQueryMetaReplyMoreInfo, traceDC)
}
func traceJimm06000D2(b []byte) ([]string, error) {
	return tracePacket(b, wire.ICQDBQueryMetaReply, wire.ICQDBQueryMetaReplyWorkInfo, traceD2)
}
func traceJimm06000E6(b []byte) ([]string, error) {
	return tracePacket(b, wire.ICQDBQueryMetaReply, wire.ICQDBQueryMetaReplyNotes, traceE6)
}
func traceJimm06000FA(b []byte) ([]string, error) {
	return tracePacket(b, wire.ICQDBQueryMetaReply, wire.ICQDBQueryMetaReplyAffiliations, traceFA)
}

func tracePacket(b []byte, wantReqType, wantSubType uint16, fn func(*auditTracer) error) ([]string, error) {
	t := &auditTracer{r: bytes.NewReader(b)}
	if err := t.metaHeader(wantReqType, wantSubType); err != nil {
		return t.lines, err
	}
	if err := fn(t); err != nil {
		return t.lines, err
	}
	if err := t.ensureEOF(); err != nil {
		return t.lines, err
	}
	return t.lines, nil
}

type auditTracer struct {
	r     *bytes.Reader
	lines []string
}

func (t *auditTracer) off() int {
	return int(t.r.Size() - int64(t.r.Len()))
}

func (t *auditTracer) addSpan(start int, format string, args ...any) {
	t.lines = append(t.lines, fmt.Sprintf("off=%d..%d %s", start, t.off(), fmt.Sprintf(format, args...)))
}

func (t *auditTracer) metaHeader(wantReqType, wantSubType uint16) error {
	uin, err := t.readUint32LE("uin")
	if err != nil {
		return err
	}
	if uin == 0 {
		return fmt.Errorf("uin is zero")
	}
	reqType, err := t.readUint16LE("req_type")
	if err != nil {
		return err
	}
	if reqType != wantReqType {
		return fmt.Errorf("req_type=%#x want %#x", reqType, wantReqType)
	}
	seq, err := t.readUint16LE("seq")
	if err != nil {
		return err
	}
	if seq == 0 {
		return fmt.Errorf("seq is zero")
	}
	subType, err := t.readUint16LE("sub_type")
	if err != nil {
		return err
	}
	if subType != wantSubType {
		return fmt.Errorf("sub_type=%#x want %#x", subType, wantSubType)
	}
	if _, err := t.readUint8LE("success"); err != nil {
		return err
	}
	return nil
}

func (t *auditTracer) readICQSString(label string) (string, error) {
	start := t.off()
	n, err := t.readUint16LE(label + ".len")
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("%s length is zero", label)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.r, buf); err != nil {
		return "", err
	}
	if buf[len(buf)-1] != 0x00 {
		return "", fmt.Errorf("%s missing null terminator", label)
	}
	t.addSpan(start, "%s=%q", label, string(buf[:len(buf)-1]))
	return string(buf[:len(buf)-1]), nil
}

func (t *auditTracer) readUint8LE(label string) (uint8, error) {
	start := t.off()
	var v uint8
	if err := binary.Read(t.r, binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	t.addSpan(start, "%s=0x%02x", label, v)
	return v, nil
}

func (t *auditTracer) readUint16LE(label string) (uint16, error) {
	start := t.off()
	var v uint16
	if err := binary.Read(t.r, binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	t.addSpan(start, "%s=0x%04x", label, v)
	return v, nil
}

func (t *auditTracer) readUint32LE(label string) (uint32, error) {
	start := t.off()
	var v uint32
	if err := binary.Read(t.r, binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	t.addSpan(start, "%s=0x%08x", label, v)
	return v, nil
}

func (t *auditTracer) ensureEOF() error {
	if t.r.Len() != 0 {
		rest := make([]byte, t.r.Len())
		if _, err := io.ReadFull(t.r, rest); err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing bytes: %s", hex.EncodeToString(rest))
	}
	return nil
}

func traceC8(t *auditTracer) error {
	for _, label := range []string{"nickname", "first_name", "last_name", "email", "city", "state", "phone", "fax", "address", "cell_phone"} {
		if _, err := t.readICQSString(label); err != nil {
			return err
		}
	}
	return nil
}

func traceDC(t *auditTracer) error {
	if _, err := t.readUint16LE("age"); err != nil {
		return err
	}
	if _, err := t.readUint8LE("gender"); err != nil {
		return err
	}
	if _, err := t.readICQSString("home_page"); err != nil {
		return err
	}
	if _, err := t.readUint16LE("birth_year"); err != nil {
		return err
	}
	if _, err := t.readUint8LE("birth_month"); err != nil {
		return err
	}
	if _, err := t.readUint8LE("birth_day"); err != nil {
		return err
	}
	return nil
}

func traceD2(t *auditTracer) error {
	for _, label := range []string{"city", "state", "phone", "fax", "address", "zip"} {
		if _, err := t.readICQSString(label); err != nil {
			return err
		}
	}
	if _, err := t.readUint16LE("country_code"); err != nil {
		return err
	}
	for _, label := range []string{"company", "department", "position", "web_page"} {
		if _, err := t.readICQSString(label); err != nil {
			return err
		}
	}
	return nil
}

func traceE6(t *auditTracer) error {
	_, err := t.readICQSString("notes")
	return err
}

func traceFA(t *auditTracer) error {
	// Jimm 0.6.0 consumes only the success byte for this reply.
	return nil
}
