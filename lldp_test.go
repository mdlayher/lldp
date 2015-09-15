package lldp

import (
	"bytes"
	"io"
	"log"
	"math"
	"testing"
	"time"
)

func TestFrameMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		f    *Frame
		b    []byte
		err  error
	}{
		{
			desc: "ChassisID nil",
			f:    &Frame{},
			err:  ErrInvalidFrame,
		},
		{
			desc: "PortID nil",
			f: &Frame{
				ChassisID: &ChassisID{},
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "TTL too large",
			f: &Frame{
				ChassisID: &ChassisID{},
				PortID:    &PortID{},
				TTL:       (math.MaxUint16 + 1) * time.Second,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "too much data in ChassisID",
			f: &Frame{
				ChassisID: &ChassisID{
					ID: make([]byte, TLVLengthMax+1),
				},
				PortID: &PortID{},
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "too much data in PortID",
			f: &Frame{
				ChassisID: &ChassisID{},
				PortID: &PortID{
					ID: make([]byte, TLVLengthMax+1),
				},
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "length mismatch in optional TLV",
			f: &Frame{
				ChassisID: &ChassisID{},
				PortID:    &PortID{},
				Optional: []*TLV{
					{
						Type:   0,
						Length: 2,
						Value:  []byte{1},
					},
				},
			},
			err: ErrInvalidTLV,
		},
		{
			desc: "OK",
			f: &Frame{
				ChassisID: &ChassisID{
					Subtype: 1,
					ID:      []byte("foo"),
				},
				PortID: &PortID{
					Subtype: 1,
					ID:      []byte("bar"),
				},
				TTL: 255 * time.Second,
			},
			b: []byte{
				0x02, 0x04, 1, 'f', 'o', 'o',
				0x04, 0x04, 1, 'b', 'a', 'r',
				0x06, 0x02, 0, 255,
				0, 0,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.f.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected Frame bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestFrameUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		f    *Frame
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
			desc: "first TLV with incorrect length field",
			b:    []byte{0x02, 0xff},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "second TLV with incorrect length field",
			b: []byte{
				0x02, 0x00,
				0x02, 0xff,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "first TLV not chassis ID type",
			b: []byte{
				0x04, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "second TLV not port ID type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x02, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "third TLV not TTL type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x04, 0x00,
				0x00, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "third TLV is TTL type but not uint16",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x01, 0x00,
				0x00, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "fourth TLV is not end of LLDPDU type",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x02, 0x00, 0x00,
				0x02, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "fourth TLV is end of LLDPDU type, but not length zero",
			b: []byte{
				0x02, 0x01, 0x00,
				0x04, 0x01, 0x00,
				0x06, 0x02, 0x00, 0x00,
				0x00, 0x01, 0x00,
			},
			err: ErrInvalidFrame,
		},
		{
			desc: "OK Frame, no optional TLVs",
			b: []byte{
				0x02, 0x05, 6, 'e', 't', 'h', '0',
				0x04, 0x05, 4, 'e', 't', 'h', '1',
				0x06, 0x02, 0x00, 0xff,
				0x00, 0x00,
			},
			f: &Frame{
				ChassisID: &ChassisID{
					Subtype: 6,
					ID:      []byte("eth0"),
				},
				PortID: &PortID{
					Subtype: 4,
					ID:      []byte("eth1"),
				},
				TTL: 255 * time.Second,
			},
		},
		{
			desc: "OK Frame, two optional TLVs",
			b: []byte{
				0x02, 0x05, 6, 'e', 't', 'h', '0',
				0x04, 0x05, 4, 'e', 't', 'h', '1',
				0x06, 0x02, 0x00, 0xff,
				0x08, 0x01, 1,
				0x0a, 0x02, 1, 2,
				0x00, 0x00,
			},
			f: &Frame{
				ChassisID: &ChassisID{
					Subtype: 6,
					ID:      []byte("eth0"),
				},
				PortID: &PortID{
					Subtype: 4,
					ID:      []byte("eth1"),
				},
				TTL: 255 * time.Second,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		f := new(Frame)
		if err := f.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		fb, err := f.MarshalBinary()
		if err != nil {
			log.Fatal(err)
		}

		if want, got := tt.b, fb; !bytes.Equal(want, got) {
			t.Fatalf("unexpected Frame bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
