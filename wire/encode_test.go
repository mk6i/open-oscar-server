package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// errWriter is a writer that always returns an error.
type errWriter struct{}

func (errWriter) Write(p []byte) (n int, err error) {
	return 0, io.EOF
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name    string
		w       io.Writer
		given   any
		want    []byte
		wantErr error
	}{
		{
			name: "marshal uint8",
			w:    &bytes.Buffer{},
			given: struct {
				Val uint8
			}{
				Val: 100,
			},
			want: []byte{0x64},
		},
		{
			name: "marshal uint16",
			w:    &bytes.Buffer{},
			given: struct {
				Val uint16
			}{
				Val: 100,
			},
			want: []byte{0x0, 0x64},
		},
		{
			name: "marshal uint32",
			w:    &bytes.Buffer{},
			given: struct {
				Val uint32
			}{
				Val: 100,
			},
			want: []byte{0x0, 0x0, 0x0, 0x64},
		},
		{
			name: "marshal uint64",
			w:    &bytes.Buffer{},
			given: struct {
				Val uint64
			}{
				Val: 100,
			},
			want: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x64},
		},
		{
			name: "unsupported type",
			w:    &bytes.Buffer{},
			given: struct {
				Val int16
			}{
				Val: 100,
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "string8",
			w:    &bytes.Buffer{},
			given: struct {
				Val string `oscar:"len_prefix=uint8"`
			}{
				Val: "test-value",
			},
			want: append(
				[]byte{0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "string8 write error",
			w:    errWriter{},
			given: struct {
				Val string `oscar:"len_prefix=uint8"`
			}{
				Val: "test-value",
			},
			wantErr: io.EOF,
		},
		{
			name: "string16",
			w:    &bytes.Buffer{},
			given: struct {
				Val string `oscar:"len_prefix=uint16"`
			}{
				Val: "test-value",
			},
			want: append(
				[]byte{0x0, 0xa}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}...), /* str val */
		},
		{
			name: "null-terminated string16",
			w:    &bytes.Buffer{},
			given: struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "test-value",
			},
			want: append(
				[]byte{0x0, 0xb}, /* len prefix */
				[]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00}...), /* str val */
		},
		{
			name: "null-terminated string16 with len 0",
			w:    &bytes.Buffer{},
			given: struct {
				Val string `oscar:"len_prefix=uint16,nullterm"`
			}{
				Val: "",
			},
			want: []byte{0x0, 0x0}, /* len prefix */
		},
		{
			name: "string16 write error",
			w:    errWriter{},
			given: struct {
				Val string `oscar:"len_prefix=uint16"`
			}{
				Val: "test-value",
			},
			wantErr: io.EOF,
		},
		{
			name: "string with unknown prefix type",
			w:    &bytes.Buffer{},
			given: struct {
				Val string `oscar:"len_prefix=uint128"`
			}{
				Val: "test-value",
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "byte slice with no prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte
			}{
				Val: []byte(`hello`),
			},
			want: []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
		},
		{
			name: "byte slice with no prefix with write error",
			w:    &bytes.Buffer{},
			given: struct {
				Val []int
			}{
				Val: []int{1, 2, 3, 4},
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "byte slice with no prefix with write error",
			w:    errWriter{},
			given: struct {
				Val []byte
			}{
				Val: []byte(`hello`),
			},
			wantErr: io.EOF,
		},
		{
			name: "empty byte slice",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte
			}{
				Val: []byte{},
			},
			want: []byte(nil),
		},
		{
			name: "byte slice with uint8 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{
				Val: []byte(`hello`),
			},
			want: append(
				[]byte{0x05},                             /* len prefix */
				[]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}...), /* slice val */
		},
		{
			name: "byte slice with uint8 len_prefix with error",
			w:    errWriter{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint8"`
			}{
				Val: []byte(`hello`),
			},
			wantErr: io.EOF,
		},
		{
			name: "byte slice with uint16 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint16"`
			}{
				Val: []byte(`hello`),
			},
			want: append(
				[]byte{0x00, 0x05},                       /* len prefix */
				[]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}...), /* slice val */
		},
		{
			name: "byte slice with uint16 len_prefix with error",
			w:    errWriter{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint16"`
			}{
				Val: []byte(`hello`),
			},
			wantErr: io.EOF,
		},
		{
			name: "empty struct slice",
			w:    &bytes.Buffer{},
			given: struct {
				Val []TLV
			}{
				Val: []TLV{},
			},
			want: []byte(nil),
		},
		{
			name: "struct slice with invalid type in struct",
			w:    &bytes.Buffer{},
			given: struct {
				Val []struct {
					Val int16
				}
			}{
				Val: []struct {
					Val int16
				}{
					{
						Val: 1234,
					},
				},
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "struct slice with uint8 count_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []TLV `oscar:"count_prefix=uint8"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			want: append(
				[]byte{0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint8 count_prefix with error",
			w:    errWriter{},
			given: struct {
				Val []TLV `oscar:"count_prefix=uint8"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
				},
			},
			wantErr: io.EOF,
		},
		{
			name: "struct slice with uint16 count_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []TLV `oscar:"count_prefix=uint16"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			want: append(
				[]byte{0x00, 0x02}, /* count prefix */
				[]byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2}...), /* slice val */
		},
		{
			name: "struct slice with uint16 count_prefix with error",
			w:    errWriter{},
			given: struct {
				Val []TLV `oscar:"count_prefix=uint16"`
			}{
				Val: []TLV{
					NewTLVBE(10, uint16(1234)),
				},
			},
			wantErr: io.EOF,
		},
		{
			name: "byte slice with uint16 len_prefix and uint16 count_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint16,count_prefix=uint16"`
			}{
				Val: []byte(`hello`),
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "byte slice with unknown len_prefix type",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte `oscar:"len_prefix=uint128"`
			}{
				Val: []byte(`hello`),
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "byte slice with unknown count_prefix type",
			w:    &bytes.Buffer{},
			given: struct {
				Val []byte `oscar:"count_prefix=uint128"`
			}{
				Val: []byte(`hello`),
			},
			wantErr: errInvalidStructTag,
		},
		{
			name:    "empty snac",
			w:       &bytes.Buffer{},
			given:   nil,
			wantErr: errMarshalFailureNilSNAC,
		},
		{
			name: "struct with uint8 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
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
			want: []byte{
				0x22,       // Val0
				0x03,       // Val1 struct len
				0x00, 0x10, // Val2
				0x0A,       // Val3
				0x00, 0x20, // Val2
			},
		},
		{
			name: "struct with uint16 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
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
			want: []byte{
				0x22,       // Val0
				0x00, 0x03, // Val1 struct len
				0x00, 0x10, // Val2
				0x0A,       // Val3
				0x00, 0x20, // Val2
			},
		},
		{
			name: "invalid struct with uint16 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 struct {
					Val2 int
				} `oscar:"len_prefix=uint16"`
			}{
				Val1: struct {
					Val2 int
				}{
					Val2: 16,
				},
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "empty struct with uint16 len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 struct {
				} `oscar:"len_prefix=uint16"`
			}{
				Val1: struct {
				}{},
			},
			want: []byte{
				0x00, 0x00, // 0-len
			},
		},
		{
			name: "struct with unknown len_prefix",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 struct {
					Val2 uint16
				} `oscar:"len_prefix=uint128"`
			}{
				Val1: struct {
					Val2 uint16
				}{
					Val2: 16,
				},
			},
			wantErr: errInvalidStructTag,
		},
		{
			name: "optional struct has value",
			w:    &bytes.Buffer{},
			given: struct {
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
			want: []byte{
				0x00, 0x22, // Val0
				0x00, 0x64, // Val1
			},
		},
		{
			name: "optional struct with value missing `optional` struct tag",
			w:    &bytes.Buffer{},
			given: struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				}
			}{
				Val0: 34,
				Optional: &struct {
					Val1 uint16
				}{
					Val1: 100,
				},
			},
			wantErr: errNonOptionalPointer,
		},
		{
			name: "optional struct doesn't have value",
			w:    &bytes.Buffer{},
			given: struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
			}{
				Val0:     34,
				Optional: nil,
			},
			want: []byte{
				0x00, 0x22, // Val0
			},
		},
		{
			name: "optional struct not last field throws error",
			w:    &bytes.Buffer{},
			given: struct {
				Optional *struct {
					Val1 uint16
				} `oscar:"optional"`
				Val0 uint16
			}{
				Optional: nil,
				Val0:     34,
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "optional non-pointer struct field throws error",
			w:    &bytes.Buffer{},
			given: struct {
				Optional *string `oscar:"optional"`
			}{
				Optional: func() *string {
					v := "blahblah"
					return &v
				}(),
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "non-struct pointer value throws error",
			w:    &bytes.Buffer{},
			given: func() *string {
				v := "blahblah"
				return &v
			}(),
			wantErr: ErrMarshalFailure,
		},
		{
			name: "optional struct with uint16 len_prefix and value",
			w:    &bytes.Buffer{},
			given: struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"len_prefix=uint16,optional"`
			}{
				Val0: 34,
				Optional: &struct {
					Val1 uint16
				}{
					Val1: 100,
				},
			},
			want: []byte{
				0x00, 0x22, // Val0
				0x00, 0x02, // Val0
				0x00, 0x64, // Val1
			},
		},
		{
			name: "optional struct with uint16 len_prefix and no value",
			w:    &bytes.Buffer{},
			given: struct {
				Val0     uint16
				Optional *struct {
					Val1 uint16
				} `oscar:"len_prefix=uint16,optional"`
			}{
				Val0:     34,
				Optional: nil,
			},
			want: []byte{
				0x00, 0x22, // Val0
			},
		},
		{
			name: "optional field that isn't a pointer is unsupported",
			w:    &bytes.Buffer{},
			given: struct {
				Val0     uint16
				Optional struct {
					Val1 uint16
				} `oscar:"len_prefix=uint16,optional"`
			}{
				Val0: 34,
				Optional: struct {
					Val1 uint16
				}{
					Val1: 100,
				},
			},
			wantErr: errOptionalNonPointer,
		},
		{
			name: "optional field that isn't a pointer to a struct is unsupported",
			w:    &bytes.Buffer{},
			given: struct {
				Optional *string `oscar:"len_prefix=uint16,optional"`
			}{
				Optional: func() *string {
					v := "blahblah"
					return &v
				}(),
			},
			wantErr: ErrMarshalFailure,
		},
		{
			name: "struct with any type field containing a struct",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 uint8
				Val2 any
			}{
				Val1: 0x12,
				Val2: struct {
					Field1 uint16
					Field2 uint8
				}{
					Field1: 0x1234,
					Field2: 0x56,
				},
			},
			want: []byte{
				0x12,       // Val1
				0x12, 0x34, // Val2.Field1 (uint16)
				0x56, // Val2.Field2 (uint8)
			},
		},
		{
			name: "struct with any type field containing an empty struct",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 uint8
				Val2 any
			}{
				Val1: 0x12,
				Val2: struct{}{}, // empty struct
			},
			want: []byte{
				0x12, // Val1
			},
		},
		{
			name: "struct with any type field containing a non-struct value",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 uint8
				Val2 any
			}{
				Val1: 0x12,
				Val2: "non-struct value", // non-struct value
			},
			wantErr: ErrMarshalFailure, // expecting an error because Val2 is not a struct
		},
		{
			name: "struct with ICQMessageReplyEnvelope field",
			w:    &bytes.Buffer{},
			given: struct {
				Val1 uint16
				Val2 ICQMessageReplyEnvelope
			}{
				Val1: 0x1234,
				Val2: ICQMessageReplyEnvelope{
					Message: struct {
						Val3 uint16
					}{
						Val3: 0x1234,
					},
				},
			},
			want: []byte{
				// Big-endian encoding for Val1
				0x12, 0x34, // Val1
				// Little-endian encoding for Val2.Message.Val3
				0x2, 0x0, // Val2 len
				0x34, 0x12, // Val2.Message.Val3
			},
		},
		{
			name: "byte array",
			w:    &bytes.Buffer{},
			given: struct {
				Val [5]byte
			}{
				Val: [5]byte{'h', 'e', 'l', 'l', 'o'},
			},
			want: []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
		},
		{
			name: "byte array with error",
			w:    errWriter{},
			given: struct {
				Val [5]byte
			}{
				Val: [5]byte{'h', 'e', 'l', 'l', 'o'},
			},
			wantErr: io.EOF,
		},
		{
			name: "struct array",
			w:    &bytes.Buffer{},
			given: struct {
				Val [2]TLV
			}{
				Val: [2]TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			want: []byte{0x0, 0xa, 0x0, 0x2, 0x4, 0xd2, 0x0, 0x14, 0x0, 0x2, 0x4, 0xd2},
		},
		{
			name: "struct array with error",
			w:    errWriter{},
			given: struct {
				Val [2]TLV
			}{
				Val: [2]TLV{
					NewTLVBE(10, uint16(1234)),
					NewTLVBE(20, uint16(1234)),
				},
			},
			wantErr: io.EOF,
		},
		{
			name: "duplicate quirk keys in oscar tag",
			w:    &bytes.Buffer{},
			given: struct {
				V uint8 `oscar:"quirk=a,quirk=b"`
			}{V: 1},
			wantErr: errInvalidStructTag,
		},
		{
			name: "empty quirk value",
			w:    &bytes.Buffer{},
			given: struct {
				V uint8 `oscar:"quirk="`
			}{V: 1},
			wantErr: errInvalidStructTag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MarshalBE(tt.given, tt.w)
			assert.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr == nil {
				if w, ok := tt.w.(*bytes.Buffer); ok {
					assert.Equal(t, tt.want, w.Bytes())
				}
			}
		})
	}
}
