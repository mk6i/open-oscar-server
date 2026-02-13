package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		prototype any
		given     []byte
		want      any
		wantErr   error
	}{
		{
			name: "uint8",
			prototype: &struct {
				Val uint8
			}{},
			want: &struct {
				Val uint8
			}{
				Val: 100,
			},
			given: []byte{0x64},
		},
		{
			name: "uint8 with read error",
			prototype: &struct {
				Val uint8
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "uint16",
			prototype: &struct {
				Val uint16
			}{},
			want: &struct {
				Val uint16
			}{
				Val: 100,
			},
			given: []byte{0x0, 0x64},
		},
		{
			name: "uint16 with read error",
			prototype: &struct {
				Val uint16
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "uint32",
			prototype: &struct {
				Val uint32
			}{},
			want: &struct {
				Val uint32
			}{
				Val: 100,
			},
			given: []byte{0x0, 0x0, 0x0, 0x64},
		},
		{
			name: "uint32 with read error",
			prototype: &struct {
				Val uint32
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "uint64",
			prototype: &struct {
				Val uint64
			}{},
			want: &struct {
				Val uint64
			}{
				Val: 100,
			},
			given: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x64},
		},
		{
			name: "uint64 with read error",
			prototype: &struct {
				Val uint64
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "string8",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint8"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint8"`
			}{
				Val: "test-value",
			},
			given: append(
				[]byte{0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "string8 read error",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint8"`
			}{},
			given:   []byte{},
			wantErr: io.EOF,
		},
		{
			name: "string16",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint16"`
			}{
				Val: "test-value",
			},
			given: append(
				[]byte{0x0, 0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "null-terminated string16",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "test-value",
			},
			given: append(
				[]byte{0x0, 0xb}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00}...), /* str val */
		},
		{
			name: "null-terminated string16 with len 0",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "",
			},
			given: []byte{0x0, 0x00}, /* len prefix */
		},
		{
			name: "null-terminated string16 without null terminator",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "test-value",
			},
			given: append(
				[]byte{0x0, 0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "null-terminated string16 with null in middle",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{},
			want: &struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "test",
			},
			given: append(
				[]byte{0x0, 0xf}, /* len prefix = 15 bytes */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x00, 0x6d, 0x6f, 0x72, 0x65, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x21}...), /* "test\0more-data!" */
		},
		{
			name: "string16 read error",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint16"`
			}{},
			given:   []byte{},
			wantErr: io.EOF,
		},
		{
			name: "unsupported string prefix type",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint128"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x0, 0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "string with missing len_prefix",
			prototype: &struct {
				Val string
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x0, 0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "partial string8",
			prototype: &struct {
				Val string `oscar:"len_prefix=uint8"`
			}{},
			wantErr: io.EOF,
			given: append(
				[]byte{0xa},  /* len prefix */
				[]byte{}...), /* truncated payload */
		},
		{
			name: "byte slice with uint8 len_prefix",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{},
			want: &struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{
				Val: []byte(`hello`),
			},
			given: append(
				[]byte{0x05},                             /* len prefix */
				[]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}...), /* slice val */
		},
		{
			name: "slice of invalid type with uint8 len_prefix",
			prototype: &struct {
				Val []int `oscar:"len_prefix=uint8"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given:   []byte{0x04, 0x65, 0x6c, 0x6c, 0x6f},
		},
		{
			name: "byte slice with uint8 len_prefix with read error",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{},
			wantErr: io.EOF,
			given: append(
				[]byte{0x05}, /* len prefix */
				[]byte{}...), /* slice val */
		},
		{
			name: "byte slice with uint8 len_prefix read error",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "byte slice with uint16 len_prefix",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint16"`
			}{},
			want: &struct {
				Val []byte `oscar:"len_prefix=uint16"`
			}{
				Val: []byte(`hello`),
			},
			given: append(
				[]byte{0x00, 0x05},                       /* len prefix */
				[]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}...), /* slice val */
		},
		{
			name: "byte slice with uint16 len_prefix read error",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint16"`
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "byte slice with invalid len_prefix",
			prototype: &struct {
				Val []byte `oscar:"len_prefix=uint128"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x00, 0x05},                       /* len prefix */
				[]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}...), /* slice val */
		},
		{
			name: "struct slice without prefix",
			prototype: &struct {
				Val []TLV
			}{},
			want: &struct {
				Val []TLV
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			given: []byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2},
		},
		{
			name: "struct slice without prefix tolerates trailing garbage bytes",
			prototype: &struct {
				Val []TLV
			}{},
			want: &struct {
				Val []TLV
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
				},
			},
			// one valid TLV followed by 3 trailing garbage bytes that
			// don't form a complete TLV (simulates Jimm 0.5.1 bug)
			given: []byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0xff, 0xff, 0xff},
		},
		{
			name: "slice of unsupported type without prefix",
			prototype: &struct {
				Val []int
			}{},
			wantErr: ErrUnmarshalFailure,
			given:   []byte{0x0, 0xa, 0x0, 0x2},
		},
		{
			name: "struct slice with uint8 count_prefix",
			prototype: &struct {
				Val []TLV `oscar:"count_prefix=uint8"`
			}{},
			want: &struct {
				Val []TLV `oscar:"count_prefix=uint8"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			given: append(
				[]byte{0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint8 count_prefix and unsupported type",
			prototype: &struct {
				Val []struct {
					Val int16
				} `oscar:"count_prefix=uint8"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint8 count_prefix read error",
			prototype: &struct {
				Val []TLV `oscar:"count_prefix=uint8"`
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "struct slice with uint16 count_prefix",
			prototype: &struct {
				Val []TLV `oscar:"count_prefix=uint16"`
			}{},
			want: &struct {
				Val []TLV `oscar:"count_prefix=uint16"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			given: append(
				[]byte{0x0, 0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint16 count_prefix and unsupported type",
			prototype: &struct {
				Val []struct {
					Val int16
				} `oscar:"count_prefix=uint16"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x0, 0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint16 count_prefix read error",
			prototype: &struct {
				Val []TLV `oscar:"count_prefix=uint16"`
			}{},
			wantErr: io.EOF,
			given:   []byte{},
		},
		{
			name: "struct slice with invalid count_prefix",
			prototype: &struct {
				Val []TLV `oscar:"count_prefix=uint128"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: append(
				[]byte{0x0, 0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct with uint8 len_prefix",
			prototype: &struct {
				Val0 uint8
				Val1 struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint8"`
				Val4 uint16
			}{},
			want: &struct {
				Val0 uint8
				Val1 struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint8"`
				Val4 uint16
			}{
				Val0: 34,
				Val1: struct {
					Val2 uint16
					Val3 uint8
				}{
					Val2: 16,
					Val3: 10,
				},
				Val4: 32,
			},
			given: []byte{
				0x22,       // Val0
				0x03,       // Val1 struct len
				0x00, 0x10, // Val2
				0x0A,       // Val3
				0x00, 0x20, // Val2
			},
		},
		{
			name: "struct with uint16 len_prefix",
			prototype: &struct {
				Val0 uint8
				Val1 struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16"`
				Val4 uint16
			}{},
			want: &struct {
				Val0 uint8
				Val1 struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16"`
				Val4 uint16
			}{
				Val0: 34,
				Val1: struct {
					Val2 uint16
					Val3 uint8
				}{
					Val2: 16,
					Val3: 10,
				},
				Val4: 32,
			},
			given: []byte{
				0x22,       // Val0
				0x00, 0x03, // Val1 struct len
				0x00, 0x10, // Val2
				0x0A,       // Val3
				0x00, 0x20, // Val2
			},
		},
		{
			name: "struct with uint16 len_prefix with read error",
			prototype: &struct {
				Val1 struct {
					Val2 uint16
				} `oscar:"len_prefix=uint16"`
			}{},
			given: []byte{
				0x00, 0x10, // 16 byte len, but the body is truncated
			},
			wantErr: io.EOF,
		},
		{
			name: "struct with unknown len_prefix",
			prototype: &struct {
				Val1 struct {
					Val2 uint16
				} `oscar:"len_prefix=uint128"`
			}{},
			wantErr: ErrUnmarshalFailure,
		},
		{
			name: "optional struct has value",
			prototype: &struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
			}{},
			want: &struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
			}{
				Val0: 34,
				Optional: &struct {
					Val1 uint16
				}{
					Val1: 100,
				},
			},
			given: []byte{
				0x00, 0x22, // Val0
				0x00, 0x64, // Val1
			},
		},
		{
			name: "optional struct with value missing `optional` struct tag",
			prototype: &struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				}
			}{},
			given: []byte{
				0x00, 0x22, // Val0
				0x00, 0x64, // Val1
			},
			wantErr: ErrUnmarshalFailure,
		},
		{
			name: "optional struct doesn't have value",
			prototype: &struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
			}{},
			want: &struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
			}{
				Val0:     34,
				Optional: nil,
			},
			given: []byte{
				0x00, 0x22, // Val0
			},
		},
		{
			name: "optional struct followed by value throws error",
			prototype: &struct {
				Optional *struct {
					Val0 uint16
				} `oscar:"optional"`
				Val1 uint16
			}{},
			wantErr: ErrUnmarshalFailure,
			given: []byte{
				0x00, 0x22, // Val0
				0x00, 0x22, // Val1
			},
		},
		{
			name: "optional non-struct field throws error",
			prototype: &struct {
				Optional *uint16 `oscar:"optional"`
			}{},
			wantErr: ErrUnmarshalFailure,
			given: []byte{
				0x00, 0x22, // Val0
			},
		},
		{
			name: "non-struct pointer value throws error",
			prototype: func() any {
				val := 10
				ptr1 := &val
				return &ptr1
			}(),
			wantErr: ErrUnmarshalFailure,
			given: []byte{
				0x00, 0x22, // Val0
			},
		},
		{
			name: "optional struct with uint16 len_prefix and value",
			prototype: &struct {
				Val0 uint8
				Val1 *struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16,optional"`
			}{},
			want: &struct {
				Val0 uint8
				Val1 *struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16,optional"`
			}{
				Val0: 34,
				Val1: &struct {
					Val2 uint16
					Val3 uint8
				}{
					Val2: 16,
					Val3: 10,
				},
			},
			given: []byte{
				0x22,       // Val0
				0x00, 0x03, // Val1 struct len
				0x00, 0x10, // Val2
				0x0A,       // Val3
				0x00, 0x20, // Val2
			},
		},
		{
			name: "optional struct with uint16 len_prefix and no value",
			prototype: &struct {
				Val0 uint8
				Val1 *struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16,optional"`
			}{},
			want: &struct {
				Val0 uint8
				Val1 *struct {
					Val2 uint16
					Val3 uint8
				} `oscar:"len_prefix=uint16,optional"`
			}{
				Val0: 34,
				Val1: nil,
			},
			given: []byte{
				0x22, // Val0
			},
		},
		{
			name: "optional field that isn't a pointer to a struct is unsupported",
			prototype: &struct {
				Val1 *string `oscar:"optional"`
			}{},
			given: []byte{
				0x00,
			},
			wantErr: errNonOptionalPointer,
		},
		{
			name: "byte array",
			prototype: &struct {
				Val [5]byte
			}{},
			want: &struct {
				Val [5]byte
			}{
				Val: [5]byte{'h', 'e', 'l', 'l', 'o'},
			},
			given: []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
		},
		{
			name: "array of invalid type",
			prototype: &struct {
				Val [5]int
			}{},
			wantErr: ErrUnmarshalFailure,
			given:   []byte{1, 2, 3, 4, 5},
		},
		{
			name: "struct array",
			prototype: &struct {
				Val [2]TLV
			}{},
			want: &struct {
				Val [2]TLV
			}{
				Val: [2]TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			given: []byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := bytes.NewBuffer(tt.given)

			err := UnmarshalBE(tt.prototype, r)
			assert.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr == nil {
				assert.Equal(t, tt.want, tt.prototype)
			}
		})
	}
}
