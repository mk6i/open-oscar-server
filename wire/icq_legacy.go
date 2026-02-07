package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// ICQ Legacy Protocol Packet Structures
// Supports V2, V3, V4, and V5 protocols

// LegacyPacketHeader contains common fields for all legacy packet versions
type LegacyPacketHeader struct {
	Version uint16
	Command uint16
	SeqNum  uint16
}

// V2ClientPacket represents an ICQ V2 client packet (unencrypted)
// Format: Version(2) + Command(2) + SeqNum(2) + UIN(4) + [Parameters...]
type V2ClientPacket struct {
	Version uint16
	Command uint16
	SeqNum  uint16
	UIN     uint32
	Data    []byte // Remaining packet data
}

// V2ServerPacket represents an ICQ V2 server packet
// Format: Version(2) + Command(2) + SeqNum(2) + [Parameters...]
type V2ServerPacket struct {
	Version uint16
	Command uint16
	SeqNum  uint16
	Data    []byte // Packet payload
}

// V3ClientPacket represents an ICQ V3 client packet (with checksum)
// Format: Version(2) + Command(2) + SeqNum(2) + UIN(4) + Checksum(4) + [Parameters...]
type V3ClientPacket struct {
	Version  uint16
	Command  uint16
	SeqNum   uint16
	UIN      uint32
	Checksum uint32
	Data     []byte
}

// V3ServerPacket represents an ICQ V3 server packet
type V3ServerPacket struct {
	Version  uint16
	Command  uint16
	SeqNum   uint16
	Checksum uint32
	Data     []byte
}

// V4ClientPacket represents an ICQ V4 client packet (partially encrypted)
// Format: Version(2) + Random(2) + [Encrypted: Zero(2) + Command(2) + SeqNum1(2) + SeqNum2(2) + UIN(4) + CheckCode(4) + Parameters...]
type V4ClientPacket struct {
	Version   uint16 // Not encrypted
	Random    uint16 // Not encrypted
	Zero      uint16 // Encrypted from here
	Command   uint16
	SeqNum1   uint16
	SeqNum2   uint16
	UIN       uint32
	CheckCode uint32
	Data      []byte
}

// V4ServerPacket represents an ICQ V4 server packet
type V4ServerPacket struct {
	Version   uint16
	Random    uint16
	Zero      uint16
	Command   uint16
	SeqNum1   uint16
	SeqNum2   uint16
	CheckCode uint32
	Data      []byte
}

// V5ClientPacket represents an ICQ V5 client packet (fully encrypted)
// Format: Version(2) + Zero(4) + UIN(4) + SessionID(4) + Command(2) + SeqNum1(2) + SeqNum2(2) + CheckCode(4) + [Parameters...]
type V5ClientPacket struct {
	Version   uint16
	Zero      uint32
	UIN       uint32
	SessionID uint32
	Command   uint16
	SeqNum1   uint16
	SeqNum2   uint16
	CheckCode uint32
	Data      []byte
}

// V5ServerPacket represents an ICQ V5 server packet
// Server packet format (from iserverd):
// VERSION(2) + ZERO(1) + SESSION_ID(4) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + JUNK(4) = 21 bytes
// Checkcode is inserted at offset 0x11 (17) by PutKey
type V5ServerPacket struct {
	Version   uint16
	SessionID uint32
	Command   uint16
	SeqNum1   uint16
	SeqNum2   uint16
	UIN       uint32
	Data      []byte
}

// V5MetaPacket represents a META_USER command packet (V5)
type V5MetaPacket struct {
	SubCommand uint16
	Data       []byte
}

// UnmarshalV2ClientPacket parses a V2 client packet from raw bytes
// Supports both standard V2 format (10+ bytes with UIN in header) and
// pre-V2/early V2 format (6+ bytes without UIN in header, used by 1996 clients)
func UnmarshalV2ClientPacket(data []byte) (*V2ClientPacket, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("packet too short for V2: %d bytes", len(data))
	}

	pkt := &V2ClientPacket{
		Version: binary.LittleEndian.Uint16(data[0:2]),
		Command: binary.LittleEndian.Uint16(data[2:4]),
		SeqNum:  binary.LittleEndian.Uint16(data[4:6]),
	}

	// Check if this is a pre-V2 packet format based on command type
	// Early 1996 clients use a 6-byte header (no UIN) for certain commands
	// Commands that use pre-V2 format (UIN in data, not header):
	// - 0x04EC (FIRST_LOGIN) - 6 byte header only
	// - 0x03F2 (early login) - UIN is in data payload
	isPreV2Command := pkt.Command == ICQLegacyCmdFirstLogin ||
		pkt.Command == ICQLegacyCmdGetDeps // 0x03F2 - early login variant

	if isPreV2Command {
		// Pre-V2 format: 6-byte header, UIN is in data payload (if present)
		if len(data) > 6 {
			pkt.Data = make([]byte, len(data)-6)
			copy(pkt.Data, data[6:])
		}
	} else if len(data) >= 10 {
		// Standard V2 format: UIN is in header at offset 6
		pkt.UIN = binary.LittleEndian.Uint32(data[6:10])
		if len(data) > 10 {
			pkt.Data = make([]byte, len(data)-10)
			copy(pkt.Data, data[10:])
		}
	} else if len(data) > 6 {
		// Short packet with some data but no full UIN - treat as pre-V2
		pkt.Data = make([]byte, len(data)-6)
		copy(pkt.Data, data[6:])
	}

	return pkt, nil
}

// MarshalV2ServerPacket serializes a V2 server packet to bytes
func MarshalV2ServerPacket(pkt *V2ServerPacket) []byte {
	buf := make([]byte, 6+len(pkt.Data))
	binary.LittleEndian.PutUint16(buf[0:2], pkt.Version)
	binary.LittleEndian.PutUint16(buf[2:4], pkt.Command)
	binary.LittleEndian.PutUint16(buf[4:6], pkt.SeqNum)
	if len(pkt.Data) > 0 {
		copy(buf[6:], pkt.Data)
	}
	return buf
}

// UnmarshalV5ClientPacket parses a V5 client packet from raw bytes (after decryption)
func UnmarshalV5ClientPacket(data []byte) (*V5ClientPacket, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("packet too short for V5: %d bytes", len(data))
	}

	pkt := &V5ClientPacket{
		Version:   binary.LittleEndian.Uint16(data[0:2]),
		Zero:      binary.LittleEndian.Uint32(data[2:6]),
		UIN:       binary.LittleEndian.Uint32(data[6:10]),
		SessionID: binary.LittleEndian.Uint32(data[10:14]),
		Command:   binary.LittleEndian.Uint16(data[14:16]),
		SeqNum1:   binary.LittleEndian.Uint16(data[16:18]),
		SeqNum2:   binary.LittleEndian.Uint16(data[18:20]),
		CheckCode: binary.LittleEndian.Uint32(data[20:24]),
	}

	if len(data) > 24 {
		pkt.Data = make([]byte, len(data)-24)
		copy(pkt.Data, data[24:])
	}

	return pkt, nil
}

// MarshalV5ServerPacket serializes a V5 server packet to bytes
// Server packets are NOT encrypted, but have a checkcode added at offset 0x11
// Format: VERSION(2) + ZERO(1) + SESSION_ID(4) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
//
// CRITICAL: The "JUNK(4)" seen in iserverd source code (e.g., make_packet.cpp) refers to the
// CHECKCODE placeholder at offset 0x11 in the HEADER - it is NOT part of the data payload!
// The checkcode is computed over the packet and inserted by AddV5ServerCheckcode().
// Do NOT add extra bytes to the data payload thinking they are "JUNK" - that breaks clients!
func MarshalV5ServerPacket(pkt *V5ServerPacket) []byte {
	// Base packet without checkcode: 2 + 1 + 4 + 2 + 2 + 2 + 4 = 17 bytes
	// Then checkcode (4 bytes) + data
	buf := make([]byte, 21+len(pkt.Data))

	offset := 0

	// VERSION (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], pkt.Version)
	offset += 2

	// ZERO (1 byte)
	buf[offset] = 0x00
	offset++

	// SESSION_ID (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], pkt.SessionID)
	offset += 4

	// COMMAND (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], pkt.Command)
	offset += 2

	// SEQ1 (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], pkt.SeqNum1)
	offset += 2

	// SEQ2 (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], pkt.SeqNum2)
	offset += 2

	// UIN (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], pkt.UIN)
	offset += 4

	// CHECKCODE placeholder (4 bytes) - will be filled by AddV5ServerCheckcode
	// offset is now 17 (0x11)
	offset += 4

	// DATA
	if len(pkt.Data) > 0 {
		copy(buf[offset:], pkt.Data)
	}

	// Add checkcode
	AddV5ServerCheckcode(buf)

	return buf
}

// DetectProtocolVersion returns the protocol version from packet header
func DetectProtocolVersion(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("packet too short to detect version")
	}
	return binary.LittleEndian.Uint16(data[0:2]), nil
}

// LegacyLoginPacket represents login data common across versions
type LegacyLoginPacket struct {
	UIN      uint32
	Password string
	IP       net.IP
	Port     uint16
	Status   uint32
	Version  uint32 // Client version
}

// LegacyMessagePacket represents a message packet
type LegacyMessagePacket struct {
	FromUIN uint32
	ToUIN   uint32
	MsgType uint16
	Message string
	URL     string // For URL messages
	Desc    string // URL description
}

// LegacyUserInfo represents user information in legacy format
type LegacyUserInfo struct {
	UIN       uint32
	Nickname  string
	FirstName string
	LastName  string
	Email     string
	City      string
	State     string
	Country   uint16
	Phone     string
	Age       uint8
	Gender    uint8
	Status    uint32
	IP        net.IP
	Port      uint16
}

// LegacySearchRequest represents a user search request
type LegacySearchRequest struct {
	UIN       uint32 // For UIN search
	Nickname  string
	FirstName string
	LastName  string
	Email     string
}

// LegacyContactListPacket represents a contact list update
type LegacyContactListPacket struct {
	UINs []uint32
}

// LegacyStatusPacket represents a status change
type LegacyStatusPacket struct {
	UIN    uint32
	Status uint32
	IP     net.IP
	Port   uint16
}

// ParseLegacyString reads a null-terminated or length-prefixed string
func ParseLegacyString(r io.Reader, lenPrefix bool) (string, error) {
	if lenPrefix {
		var length uint16
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return "", err
		}
		if length == 0 {
			return "", nil
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		// Remove null terminator if present
		if len(buf) > 0 && buf[len(buf)-1] == 0 {
			buf = buf[:len(buf)-1]
		}
		return string(buf), nil
	}

	// Null-terminated string
	var buf bytes.Buffer
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			return "", err
		}
		if b[0] == 0 {
			break
		}
		buf.WriteByte(b[0])
	}
	return buf.String(), nil
}

// WriteLegacyString writes a length-prefixed string
func WriteLegacyString(w io.Writer, s string) error {
	// Include null terminator in length
	length := uint16(len(s) + 1)
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return err
	}
	if _, err := w.Write([]byte(s)); err != nil {
		return err
	}
	// Write null terminator
	_, err := w.Write([]byte{0})
	return err
}

// ParseV2LoginPacket parses a V2 login packet
// V2 LOGIN format (after header):
// PORT(4) + PASSWORD_LEN(2) + PASSWORD + X1(4) + USER_IP(4) + X2(1) + STATUS(4) + X3(4) + LOGIN_SEQ_NUM(2) + X4(4) + X5(4)
func ParseV2LoginPacket(data []byte) (*LegacyLoginPacket, error) {
	if len(data) < 15 { // Minimum: PORT(4) + PWD_LEN(2) + 1 char + null + X1(4) + IP(4)
		return nil, fmt.Errorf("login packet too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)
	pkt := &LegacyLoginPacket{}

	// Read TCP port (4 bytes, little-endian)
	var port uint32
	if err := binary.Read(r, binary.LittleEndian, &port); err != nil {
		return nil, fmt.Errorf("parsing port: %w", err)
	}
	pkt.Port = uint16(port)

	// Read password (length-prefixed string)
	password, err := ParseLegacyString(r, true)
	if err != nil {
		return nil, fmt.Errorf("parsing password: %w", err)
	}
	pkt.Password = password

	// Read X1 (4 bytes, usually 0x00000078)
	var x1 uint32
	if err := binary.Read(r, binary.LittleEndian, &x1); err != nil {
		return nil, fmt.Errorf("parsing X1: %w", err)
	}

	// Read IP (4 bytes) - stored in network byte order (big-endian)
	ip := make([]byte, 4)
	if _, err := io.ReadFull(r, ip); err != nil {
		return nil, fmt.Errorf("parsing IP: %w", err)
	}
	pkt.IP = net.IP(ip)

	// Read X2 (1 byte, usually 0x04)
	var x2 uint8
	if err := binary.Read(r, binary.LittleEndian, &x2); err != nil {
		return nil, fmt.Errorf("parsing X2: %w", err)
	}

	// Read status (4 bytes)
	if err := binary.Read(r, binary.LittleEndian, &pkt.Status); err != nil {
		return nil, fmt.Errorf("parsing status: %w", err)
	}

	// Read X3 (4 bytes, usually 0x00000002)
	var x3 uint32
	if err := binary.Read(r, binary.LittleEndian, &x3); err != nil {
		// Optional field
		return pkt, nil
	}

	// Read login sequence number (2 bytes)
	var loginSeq uint16
	if err := binary.Read(r, binary.LittleEndian, &loginSeq); err != nil {
		// Optional field
		return pkt, nil
	}

	// Read X4 (4 bytes)
	var x4 uint32
	binary.Read(r, binary.LittleEndian, &x4)

	// Read X5 (4 bytes) - contains client version info
	if err := binary.Read(r, binary.LittleEndian, &pkt.Version); err != nil {
		// Optional field
		return pkt, nil
	}

	return pkt, nil
}

// BuildV2LoginReply creates a login success response
// V2 LOGIN_REPLY format (from protocol spec):
// USER_UIN(4) + USER_IP(4) + LOGIN_SEQ_NUM(2) + X1(4) + X2(4) + X3(4) + X4(4) + X5(6) = 32 bytes
func BuildV2LoginReply(serverSeqNum uint16, clientLoginSeq uint16, uin uint32, clientIP net.IP) *V2ServerPacket {
	data := make([]byte, 32)
	offset := 0

	// USER_UIN (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// USER_IP (4 bytes) - server's view of client IP
	if clientIP != nil {
		ip4 := clientIP.To4()
		if ip4 != nil {
			copy(data[offset:offset+4], ip4)
		}
	}
	offset += 4

	// LOGIN_SEQ_NUM (2 bytes) - echoes back the client's login sequence
	binary.LittleEndian.PutUint16(data[offset:], clientLoginSeq)
	offset += 2

	// X1 (4 bytes): 01 00 01 00
	data[offset] = 0x01
	data[offset+1] = 0x00
	data[offset+2] = 0x01
	data[offset+3] = 0x00
	offset += 4

	// X2 (4 bytes): 19 00 16 00 (or 18 00 16 00)
	data[offset] = 0x19
	data[offset+1] = 0x00
	data[offset+2] = 0x16
	data[offset+3] = 0x00
	offset += 4

	// X3 (4 bytes): 8C 00 00 00
	data[offset] = 0x8C
	data[offset+1] = 0x00
	data[offset+2] = 0x00
	data[offset+3] = 0x00
	offset += 4

	// X4 (4 bytes): 78 00 05 00
	data[offset] = 0x78
	data[offset+1] = 0x00
	data[offset+2] = 0x05
	data[offset+3] = 0x00
	offset += 4

	// X5 (6 bytes): 0A 00 05 00 01 00
	data[offset] = 0x0A
	data[offset+1] = 0x00
	data[offset+2] = 0x05
	data[offset+3] = 0x00
	data[offset+4] = 0x01
	data[offset+5] = 0x00

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvHello,
		SeqNum:  serverSeqNum,
		Data:    data,
	}
}

// BuildV2BadPassword creates a bad password response
func BuildV2BadPassword(seqNum uint16) *V2ServerPacket {
	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvWrongPasswd,
		SeqNum:  seqNum,
	}
}

// BuildV2UserOnline creates a user online notification
// V2 USER_ONLINE format (from protocol spec):
// REMOTE_UIN(4) + REMOTE_IP(4) + REMOTE_PORT(4) + REMOTE_REAL_IP(4) + X1(1) + STATUS(4) + X2(4) = 25 bytes
func BuildV2UserOnline(seqNum uint16, uin uint32, status uint32, ip net.IP, port uint16) *V2ServerPacket {
	data := make([]byte, 25)
	offset := 0

	// REMOTE_UIN (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// REMOTE_IP (4 bytes) - "outer" IP address
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			copy(data[offset:offset+4], ip4)
		}
	}
	offset += 4

	// REMOTE_PORT (4 bytes) - TCP port for direct connection
	binary.LittleEndian.PutUint32(data[offset:], uint32(port))
	offset += 4

	// REMOTE_REAL_IP (4 bytes) - "inner" IP address (same as REMOTE_IP unless behind firewall)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			copy(data[offset:offset+4], ip4)
		}
	}
	offset += 4

	// X1 (1 byte): 04
	data[offset] = 0x04
	offset++

	// STATUS (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], status)
	offset += 4

	// X2 (4 bytes): 02 00 00 00
	data[offset] = 0x02
	data[offset+1] = 0x00
	data[offset+2] = 0x00
	data[offset+3] = 0x00

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvUserOnline,
		SeqNum:  seqNum,
		Data:    data,
	}
}

// BuildV2UserOffline creates a user offline notification
func BuildV2UserOffline(seqNum uint16, uin uint32) *V2ServerPacket {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], uin)

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvUserOffline,
		SeqNum:  seqNum,
		Data:    data,
	}
}

// BuildV2Ack creates an acknowledgment packet
func BuildV2Ack(seqNum uint16) *V2ServerPacket {
	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvAck,
		SeqNum:  seqNum,
	}
}

// BuildV2Message creates a message delivery packet
func BuildV2Message(seqNum uint16, fromUIN uint32, msgType uint16, message string) *V2ServerPacket {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, fromUIN)
	binary.Write(buf, binary.LittleEndian, msgType)
	WriteLegacyString(buf, message)

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvSysMsgOnline,
		SeqNum:  seqNum,
		Data:    buf.Bytes(),
	}
}

// BuildV2StatusUpdate creates a status update notification
func BuildV2StatusUpdate(seqNum uint16, uin uint32, status uint32) *V2ServerPacket {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], uin)
	binary.LittleEndian.PutUint32(data[4:8], status)

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvUserStatus,
		SeqNum:  seqNum,
		Data:    data,
	}
}

// BuildV2ContactListDone creates a contact list processed response
func BuildV2ContactListDone(seqNum uint16) *V2ServerPacket {
	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvUserListDone,
		SeqNum:  seqNum,
	}
}

// BuildV2SearchResult creates a search result packet
func BuildV2SearchResult(seqNum uint16, user *LegacyUserInfo, isLast bool) *V2ServerPacket {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, user.UIN)
	WriteLegacyString(buf, user.Nickname)
	WriteLegacyString(buf, user.FirstName)
	WriteLegacyString(buf, user.LastName)
	WriteLegacyString(buf, user.Email)
	buf.WriteByte(user.Gender)
	buf.WriteByte(user.Age)

	cmd := ICQLegacySrvSearchFound
	if isLast {
		cmd = ICQLegacySrvSearchDone
	}

	return &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: cmd,
		SeqNum:  seqNum,
		Data:    buf.Bytes(),
	}
}

// ParseV2ContactList parses a contact list packet
func ParseV2ContactList(data []byte) (*LegacyContactListPacket, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("contact list packet too short")
	}

	r := bytes.NewReader(data)
	var count uint8
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}

	pkt := &LegacyContactListPacket{
		UINs: make([]uint32, 0, count),
	}

	for i := uint8(0); i < count; i++ {
		var uin uint32
		if err := binary.Read(r, binary.LittleEndian, &uin); err != nil {
			break // May have fewer UINs than count
		}
		pkt.UINs = append(pkt.UINs, uin)
	}

	return pkt, nil
}

// ParseV2Message parses a message packet
func ParseV2Message(data []byte) (*LegacyMessagePacket, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("message packet too short")
	}

	r := bytes.NewReader(data)
	pkt := &LegacyMessagePacket{}

	if err := binary.Read(r, binary.LittleEndian, &pkt.ToUIN); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &pkt.MsgType); err != nil {
		return nil, err
	}

	msg, err := ParseLegacyString(r, true)
	if err != nil {
		return nil, err
	}
	pkt.Message = msg

	// For URL messages, parse description
	if pkt.MsgType == ICQLegacyMsgURL {
		// URL format: "description\xFEurl"
		parts := bytes.SplitN([]byte(pkt.Message), []byte{0xFE}, 2)
		if len(parts) == 2 {
			pkt.Desc = string(parts[0])
			pkt.URL = string(parts[1])
		} else {
			pkt.URL = pkt.Message
		}
	}

	return pkt, nil
}
