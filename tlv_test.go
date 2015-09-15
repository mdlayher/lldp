package lldp

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestTLVMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		tlv  *TLV
		err  error
	}{
		{
			desc: "type too large",
			tlv: &TLV{
				Type: TLVTypeMax + 1,
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "length too large",
			tlv: &TLV{
				Length: TLVLengthMax + 1,
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "length and value length mismatch",
			tlv: &TLV{
				Length: 1,
				Value:  []byte{1, 2},
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "TLV type 1, length 1, value 255",
			tlv: &TLV{
				Type:   1,
				Length: 1,
				Value:  []byte{0xff},
			},
			b: []byte{0x02, 0x01, 0xff},
		},
		{
			desc: "TLV type 127, length 511, all zero value",
			tlv: &TLV{
				Type:   TLVTypeMax,
				Length: TLVLengthMax,
				Value:  make([]byte, TLVLengthMax),
			},
			b: append([]byte{0xff, 0xff}, make([]byte, TLVLengthMax)...),
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.tlv.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected TLV bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestTLVUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		tlv  *TLV
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer",
			b:    []byte{0},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "TLV with incorrect length field",
			b:    []byte{0x02, 0xff},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "TLV type 1, length 1, value 255",
			b:    []byte{0x02, 0x01, 0xff},
			tlv: &TLV{
				Type:   1,
				Length: 1,
				Value:  []byte{0xff},
			},
		},
		{
			desc: "TLV type 0, length 0, trailing bytes",
			b:    []byte{0x00, 0x00, 0xff},
			tlv: &TLV{
				Type:   0,
				Length: 0,
				Value:  []byte{},
			},
		},
		{
			desc: "TLV type 127, length 511, all zero value",
			b:    append([]byte{0xff, 0xff}, make([]byte, TLVLengthMax)...),
			tlv: &TLV{
				Type:   TLVTypeMax,
				Length: TLVLengthMax,
				Value:  make([]byte, TLVLengthMax),
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		tlv := new(TLV)
		if err := tlv.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.tlv, tlv; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected TLV:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
