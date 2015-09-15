package lldp

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestChassisIDMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		c    *ChassisID
		b    []byte
	}{
		{
			desc: "empty ChassisID",
			c:    &ChassisID{},
			b:    []byte{0},
		},
		{
			desc: "reserved, no ID",
			c: &ChassisID{
				Subtype: 0,
				ID:      []byte{},
			},
			b: []byte{0},
		},
		{
			desc: "MAC address",
			c: &ChassisID{
				Subtype: 4,
				ID:      []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			},
			b: []byte{4, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.c.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected ChassisID bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestChassisIDUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		c    *ChassisID
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "reserved, no ID",
			b:    []byte{0},
			c: &ChassisID{
				Subtype: 0,
				ID:      []byte{},
			},
		},
		{
			desc: "MAC address",
			b:    []byte{4, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			c: &ChassisID{
				Subtype: 4,
				ID:      []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		c := new(ChassisID)
		if err := c.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			continue
		}

		if want, got := tt.c, c; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected ChassisID:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
