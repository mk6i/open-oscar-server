package wire

import (
	"encoding/binary"
	"math/rand"
)

// ICQ Legacy Protocol Encryption/Decryption
// Ported from iserverd v5crypt.cpp

// v5Table is the encryption lookup table used by V5 protocol
// This table is used for XOR-based encryption
var v5Table = [256]byte{
	0x59, 0x60, 0x37, 0x6B, 0x65, 0x62, 0x46, 0x48,
	0x53, 0x61, 0x4C, 0x59, 0x60, 0x57, 0x5B, 0x3D,
	0x5E, 0x34, 0x6D, 0x36, 0x50, 0x3F, 0x6F, 0x67,
	0x53, 0x61, 0x4C, 0x59, 0x40, 0x47, 0x63, 0x39,
	0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69,
	0x48, 0x33, 0x31, 0x64, 0x35, 0x5A, 0x4A, 0x42,
	0x56, 0x40, 0x67, 0x53, 0x41, 0x07, 0x6C, 0x49,
	0x58, 0x3B, 0x4D, 0x46, 0x68, 0x43, 0x69, 0x48,
	0x33, 0x31, 0x44, 0x65, 0x62, 0x46, 0x48, 0x53,
	0x41, 0x07, 0x6C, 0x69, 0x48, 0x33, 0x51, 0x54,
	0x5D, 0x4E, 0x6C, 0x49, 0x38, 0x4B, 0x55, 0x4A,
	0x62, 0x46, 0x48, 0x33, 0x51, 0x34, 0x6D, 0x36,
	0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x63,
	0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x35, 0x5A,
	0x6A, 0x52, 0x6E, 0x3C, 0x51, 0x34, 0x6D, 0x36,
	0x50, 0x5F, 0x5F, 0x3F, 0x4F, 0x37, 0x4B, 0x35,
	0x5A, 0x4A, 0x62, 0x66, 0x58, 0x3B, 0x4D, 0x66,
	0x58, 0x5B, 0x5D, 0x4E, 0x6C, 0x49, 0x58, 0x3B,
	0x4D, 0x66, 0x58, 0x3B, 0x4D, 0x46, 0x48, 0x53,
	0x61, 0x4C, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64,
	0x55, 0x6A, 0x32, 0x3E, 0x44, 0x45, 0x52, 0x6E,
	0x3C, 0x31, 0x64, 0x55, 0x6A, 0x52, 0x4E, 0x6C,
	0x69, 0x48, 0x53, 0x61, 0x4C, 0x39, 0x30, 0x6F,
	0x47, 0x63, 0x59, 0x60, 0x57, 0x5B, 0x3D, 0x3E,
	0x64, 0x35, 0x3A, 0x3A, 0x5A, 0x6A, 0x52, 0x4E,
	0x6C, 0x69, 0x48, 0x53, 0x61, 0x6C, 0x49, 0x58,
	0x3B, 0x4D, 0x46, 0x68, 0x63, 0x39, 0x50, 0x5F,
	0x5F, 0x3F, 0x6F, 0x67, 0x53, 0x41, 0x25, 0x41,
	0x3C, 0x51, 0x54, 0x3D, 0x5E, 0x54, 0x5D, 0x4E,
	0x4C, 0x39, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F,
	0x47, 0x43, 0x69, 0x48, 0x33, 0x51, 0x54, 0x5D,
	0x6E, 0x3C, 0x31, 0x64, 0x35, 0x5A, 0x00, 0x00,
}

// getV5Key extracts and descrambles the check code from a V5 packet to derive the decryption key
// From iserverd GetKey() function
func getV5Key(packet []byte, packetLen int) uint32 {
	if len(packet) < 0x18 {
		return 0
	}

	// Read the scrambled check code at position 0x14 (little-endian)
	check := binary.LittleEndian.Uint32(packet[0x14:0x18])

	// Descramble the check code (from iserverd GetKey)
	A1 := check & 0x0001F000
	A2 := check & 0x07C007C0
	A3 := check & 0x003E0001
	A4 := check & 0xF8000000
	A5 := check & 0x0000083E

	A1 = A1 >> 0x0C
	A2 = A2 >> 0x01
	A3 = A3 << 0x0A
	A4 = A4 >> 0x10
	A5 = A5 << 0x0F

	descrambledCheck := A5 + A1 + A2 + A3 + A4

	// Calculate the key: packetLen * 0x68656C6C + descrambledCheck
	key := uint32(packetLen)*0x68656C6C + descrambledCheck

	return key
}

// DecryptV5Packet decrypts a V5 packet in place
// From iserverd V5Decrypt() function
func DecryptV5Packet(packet []byte, sessionID uint32) {
	if len(packet) < 0x18 {
		return
	}

	// Get the packet length (the actual UDP packet size)
	packetLen := len(packet)

	// Get the decryption key
	key := getV5Key(packet, packetLen)

	// Decrypt from offset 0x0A to end of packet
	// The algorithm processes 4 bytes at a time, but skips the checkcode positions (0x14-0x17)
	// Loop: for (i=0x0a; i < pack.sizeVal+3; i+=4)
	for i := 0x0A; i < packetLen+3; i += 4 {
		k := key + uint32(v5Table[i&0xFF])

		// XOR bytes, but skip checkcode positions
		// if (i != 0x16) { buff[i] ^= ...; buff[i+1] ^= ...; }
		if i != 0x16 {
			if i < len(packet) {
				packet[i] ^= byte(k & 0x000000FF)
			}
			if i+1 < len(packet) {
				packet[i+1] ^= byte((k & 0x0000FF00) >> 8)
			}
		}

		// if (i != 0x12) { buff[i+2] ^= ...; buff[i+3] ^= ...; }
		if i != 0x12 {
			if i+2 < len(packet) {
				packet[i+2] ^= byte((k & 0x00FF0000) >> 16)
			}
			if i+3 < len(packet) {
				packet[i+3] ^= byte((k & 0xFF000000) >> 24)
			}
		}
	}
}

// calculateV5CheckCode calculates the check code for a V5 packet
// From iserverd calculate_checkcode() function
func calculateV5CheckCode(packet []byte) uint32 {
	if len(packet) < 10 {
		return 0
	}

	// number1 is calculated from specific byte positions
	B2 := packet[2]
	B4 := packet[4]
	B6 := packet[6]
	B8 := packet[8]

	var number1 uint32
	number1 += uint32(B8)
	number1 <<= 8
	number1 += uint32(B4)
	number1 <<= 8
	number1 += uint32(B2)
	number1 <<= 8
	number1 += uint32(B6)

	// r1 and r2 are random values for number2
	r1 := uint16(rand.Intn(0x10))
	r2 := uint16(rand.Intn(0xFF))

	X4 := byte(r1)
	X3 := packet[X4]
	X2 := byte(r2)
	X1 := v5Table[X2]

	var number2 uint32
	number2 += uint32(X4)
	number2 <<= 8
	number2 += uint32(X3)
	number2 <<= 8
	number2 += uint32(X2)
	number2 <<= 8
	number2 += uint32(X1)

	number2 ^= 0x00FF00FF
	cc := number1 ^ number2

	return cc
}

// EncryptV5Packet encrypts a V5 packet in place
// From iserverd V5Encrypt() function
func EncryptV5Packet(packet []byte, sessionID uint32) {
	if len(packet) < 0x18 {
		return
	}

	// Calculate check code
	cc := calculateV5CheckCode(packet)

	// Insert the checkcode at position 0x14
	packet[0x14] = byte(cc)
	packet[0x15] = byte(cc >> 8)
	packet[0x16] = byte(cc >> 16)
	packet[0x17] = byte(cc >> 24)

	packetLen := len(packet)

	// Calculate the encryption key
	key := uint32(packetLen)*0x68656C6C + cc

	// Encrypt from offset 0x0A
	// SLAB(LEN, POS) = LEN - POS >= 4 ? 4 : LEN - POS
	for pos := 0x0A; pos < packetLen; {
		slab := packetLen - pos
		if slab > 4 {
			slab = 4
		}
		if slab <= 0 {
			break
		}

		// Read bytes as little-endian uint32
		var tmpUint uint32
		for leftI := slab - 1; leftI >= 0; leftI-- {
			tmpUint <<= 8
			if pos+leftI < len(packet) {
				tmpUint |= uint32(packet[pos+leftI])
			}
		}

		// XOR with key + table value
		tmpUint ^= key + uint32(v5Table[pos&0xFF])

		// Write back
		for rightI := 0; rightI < slab; rightI++ {
			if pos < len(packet) {
				packet[pos] = byte(tmpUint >> (rightI * 8))
				pos++
			}
		}
	}

	// Put the scrambled key (for server packets, checkcode is not scrambled)
	// The checkcode is already at 0x14, but for server packets we put it at 0x11
	// Actually for server packets, iserverd uses PutKey which puts at 0x11
	// But the client expects it at 0x14, so we leave it there
}

// GenerateSessionID generates a random session ID for V5 connections
func GenerateSessionID() uint32 {
	return rand.Uint32()
}

// ScramblePassword scrambles a password for V4/V5 login
// This is used when the password is sent in the login packet
func ScramblePassword(password string) []byte {
	if len(password) == 0 {
		return nil
	}

	scrambled := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		scrambled[i] = password[i] ^ v5Table[i%256]
	}
	return scrambled
}

// UnscramblePassword unscrambles a password from V4/V5 login
func UnscramblePassword(scrambled []byte) string {
	if len(scrambled) == 0 {
		return ""
	}

	password := make([]byte, len(scrambled))
	for i := 0; i < len(scrambled); i++ {
		password[i] = scrambled[i] ^ v5Table[i%256]
	}
	return string(password)
}

// V5CheckCode is an alias for calculateV5CheckCode for backward compatibility
func V5CheckCode(packet []byte) uint32 {
	return calculateV5CheckCode(packet)
}

// V4Table is the encryption lookup table used by V4 protocol
// This is the same table as documented in dault-v4.txt and wumpus-v4.txt
// It's the ASCII text "[1] You can modify the sounds ICQ makes..."
var V4Table = [256]byte{
	0x0a, 0x5b, 0x31, 0x5d, 0x20, 0x59, 0x6f, 0x75,
	0x20, 0x63, 0x61, 0x6e, 0x20, 0x6d, 0x6f, 0x64,
	0x69, 0x66, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x73, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x20, 0x49,
	0x43, 0x51, 0x20, 0x6d, 0x61, 0x6b, 0x65, 0x73,
	0x2e, 0x20, 0x4a, 0x75, 0x73, 0x74, 0x20, 0x73,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x22, 0x53,
	0x6f, 0x75, 0x6e, 0x64, 0x73, 0x22, 0x20, 0x66,
	0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x22, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65,
	0x6e, 0x63, 0x65, 0x73, 0x2f, 0x6d, 0x69, 0x73,
	0x63, 0x22, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x43,
	0x51, 0x20, 0x6f, 0x72, 0x20, 0x66, 0x72, 0x6f,
	0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x22, 0x53,
	0x6f, 0x75, 0x6e, 0x64, 0x73, 0x22, 0x20, 0x69,
	0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, 0x70, 0x61,
	0x6e, 0x65, 0x6c, 0x2e, 0x20, 0x43, 0x72, 0x65,
	0x64, 0x69, 0x74, 0x3a, 0x20, 0x45, 0x72, 0x61,
	0x6e, 0x0a, 0x5b, 0x32, 0x5d, 0x20, 0x43, 0x61,
	0x6e, 0x27, 0x74, 0x20, 0x72, 0x65, 0x6d, 0x65,
	0x6d, 0x62, 0x65, 0x72, 0x20, 0x77, 0x68, 0x61,
	0x74, 0x20, 0x77, 0x61, 0x73, 0x20, 0x73, 0x61,
	0x69, 0x64, 0x3f, 0x20, 0x20, 0x44, 0x6f, 0x75,
	0x62, 0x6c, 0x65, 0x2d, 0x63, 0x6c, 0x69, 0x63,
	0x6b, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x75,
	0x73, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x67,
	0x65, 0x74, 0x20, 0x61, 0x20, 0x64, 0x69, 0x61,
	0x6c, 0x6f, 0x67, 0x20, 0x6f, 0x66, 0x20, 0x61,
	0x6c, 0x6c, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x73, 0x20, 0x73, 0x65, 0x6e, 0x74,
	0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e,
}

// V5EncryptionKey derives the V5 encryption key (for backward compatibility)
func V5EncryptionKey(sessionID uint32, checkCode uint32) uint32 {
	// This is not used in the new implementation
	return 0
}


// V4 Protocol Encryption/Decryption
// V4 uses a simpler encryption scheme than V5

// V4CheckCode calculates the checksum for a V4 packet
// The checksum is calculated from specific bytes in the packet
func V4CheckCode(packet []byte) uint32 {
	if len(packet) < 10 {
		return 0
	}

	// Calculate first part of checksum from fixed positions
	chk1 := uint32(packet[8])<<24 | uint32(packet[4])<<16 |
		uint32(packet[2])<<8 | uint32(packet[6])

	// Calculate second part using random position
	r1 := rand.Intn(len(packet)-5) + 1
	r2 := rand.Intn(256)

	chk2 := uint32(r1)<<24 | uint32(packet[r1])<<16 |
		uint32(r2)<<8 | uint32(v5Table[r2])

	return chk1 ^ chk2
}

// V4EncryptionKey derives the encryption key from packet length and checksum
func V4EncryptionKey(packetLen int, checkCode uint32) uint32 {
	return uint32(packetLen)*0x66756B65 + checkCode
}

// EncryptV4Packet encrypts a V4 packet in place
// Only the first quarter of the packet (after version and random) is encrypted
func EncryptV4Packet(packet []byte, key uint32) {
	if len(packet) < 8 {
		return
	}

	// Encryption starts at offset 4 (after version and random)
	encryptStart := 4
	// Encrypt only first quarter of remaining data
	encryptLen := (len(packet) - encryptStart) / 4
	if encryptLen < 1 {
		encryptLen = 1
	}

	keyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyBytes, key)

	for i := 0; i < encryptLen; i++ {
		idx := encryptStart + i
		if idx >= len(packet) {
			break
		}
		tableIdx := byte(i&0xFF) ^ keyBytes[i%4]
		packet[idx] ^= v5Table[tableIdx]
	}
}

// DecryptV4Packet decrypts a V4 packet in place
// Decryption is the same operation as encryption (XOR is symmetric)
func DecryptV4Packet(packet []byte, key uint32) {
	EncryptV4Packet(packet, key)
}


// AddV5ServerCheckcode calculates and adds the checkcode to a V5 server packet
// Server packets are NOT encrypted, but have a checkcode at offset 0x11 (17)
// From iserverd PutKey() function
func AddV5ServerCheckcode(packet []byte) {
	if len(packet) < 21 {
		return
	}

	// Calculate checkcode using the same algorithm as for client packets
	cc := calculateV5CheckCode(packet)

	// Server checkcode is NOT scrambled (unlike client packets)
	// Insert at offset 0x11 (17)
	binary.LittleEndian.PutUint32(packet[0x11:], cc)
}

// SetV3Checkcode calculates and sets the checkcode for a V3 server packet
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// The checkcode is at offset 12 (bytes 12-15)
// From v4-notes.txt documentation (wumpus create_icq3_header function):
// First part: pack bytes 8, 4, 2, 6 (MSB to LSB)
// Second part: (random offset into table << 8) | (byte at that table offset)
// XOR second part with 0x00FF00FF, then XOR both parts together
func SetV3Checkcode(packet []byte) {
	if len(packet) < 16 {
		return
	}

	// First part: pack bytes 8, 4, 2, 6 (MSB to LSB)
	// checkA = (byte8 << 24) | (byte4 << 16) | (byte2 << 8) | byte6
	checkA := uint32(packet[8])<<24 | uint32(packet[4])<<16 | uint32(packet[2])<<8 | uint32(packet[6])

	// Second part: use a random offset into the v5Table
	// For simplicity, use a fixed offset based on packet content
	tableOffset := int(packet[0]) ^ int(packet[2]) ^ int(packet[4]) ^ int(packet[6])
	tableOffset &= 0xFF

	// checkB = (tableOffset << 8) | v5Table[tableOffset]
	checkB := uint32(tableOffset)<<8 | uint32(v5Table[tableOffset])

	// XOR checkB with 0x00FF00FF
	checkB ^= 0x00FF00FF

	// Final checkcode is checkA XOR checkB
	checkcode := checkA ^ checkB

	// Set checkcode at offset 12
	binary.LittleEndian.PutUint32(packet[12:16], checkcode)
}
