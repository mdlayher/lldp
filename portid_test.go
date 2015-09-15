package lldp

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestPortIDMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		p    *PortID
		b    []byte
	}{
		{
			desc: "empty PortID",
			p:    &PortID{},
			b:    []byte{0},
		},
		{
			desc: "reserved, no ID",
			p: &PortID{
				Subtype: 0,
				ID:      []byte{},
			},
			b: []byte{0},
		},
		{
			desc: "MAC address",
			p: &PortID{
				Subtype: 3,
				ID:      []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			},
			b: []byte{3, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected PortID bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestPortIDUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		p    *PortID
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "reserved, no ID",
			b:    []byte{0},
			p: &PortID{
				Subtype: 0,
				ID:      []byte{},
			},
		},
		{
			desc: "MAC address",
			b:    []byte{3, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			p: &PortID{
				Subtype: 3,
				ID:      []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		p := new(PortID)
		if err := p.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected PortID:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
