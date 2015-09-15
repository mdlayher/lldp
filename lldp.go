// Package lldp implements marshaling and unmarshaling of IEEE 802.1AB Link
// Layer Discovery Protocol frames.
package lldp

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"

	"github.com/mdlayher/ethernet"
)

//go:generate stringer -output=string.go -type=ChassisIDSubtype,PortIDSubtype

const (
	// EtherType is the registered EtherType for the Link Layer Discovery
	// Protocol, when the protocol is encapsulated in a IEEE 802.3 Ethernet
	// frame.
	EtherType ethernet.EtherType = 0x88cc
)

var (
	// ErrInvalidFrame is returned when a Frame (LLDPDU) is invalid due to
	// one of the following reasons:
	//  - Any of the four mandatory TLV values are not present, or are in
	//    an incorrect order:
	//    - Chassis ID
	//    - Port ID
	//    - TTL
	//    - End of LLDPDU
	ErrInvalidFrame = errors.New("invalid frame")
)

// TODO(mdlayher): consider adding common, but not mandatory, TLV values as
// top-level fields in Frame.

// A Frame is a LLDP frame, or LLDP Data Unit (LLDPDU).  A Frame carries
// device information in a series of type-length-value (TLV) structures.
type Frame struct {
	// ChassisID specifies mandatory chassis ID information regarding
	// a device.  It contains information which identifies a particular
	// chassis on a given network.
	ChassisID *ChassisID

	// PortID specifies mandatory port ID information regarding a device.
	// It contains information which identifies a particular port within
	// the context of a system, on a given network.
	PortID *PortID

	// TTL specifies a mandatory time-to-live value which indicates how long
	// information within a Frame should be considered valid.
	TTL time.Duration

	// Optional specifies zero or more optional TLV values in raw format.
	Optional []*TLV
}

// MarshalBinary allocates a byte slice and marshals a Frame into binary form.
//
// If ChassisID or Port ID are nil, or TTL is greater than 65535 seconds,
// ErrInvalidFrame is returned.
//
// If any problems are detected with TLVs, ErrInvalidTLV is returned.
func (f *Frame) MarshalBinary() ([]byte, error) {
	// TODO(mdlayher): optimize to reduce allocations

	// TODO(mdlayher): attempt to simplify by using a loop instead of
	// marshaling and packing each TLV

	// Sanity checks to avoid panics
	if f.ChassisID == nil {
		return nil, ErrInvalidFrame
	}
	if f.PortID == nil {
		return nil, ErrInvalidFrame
	}

	// Ensure TTL fits in a uint16
	tTTL := f.TTL / time.Second
	if tTTL > math.MaxUint16 {
		return nil, ErrInvalidFrame
	}
	ttl := uint16(tTTL)

	b := make([]byte, f.length())

	// Track offset into buffer
	var n int

	// Store chassis ID as first TLV
	cb, err := f.ChassisID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	cTLV := &TLV{
		Type:   TLVTypeChassisID,
		Length: uint16(len(cb)),
		Value:  cb,
	}
	cbb, err := cTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	n += len(cbb)
	copy(b[0:n], cbb)

	// Store port ID as second TLV
	pb, err := f.PortID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pTLV := &TLV{
		Type:   TLVTypePortID,
		Length: uint16(len(pb)),
		Value:  pb,
	}
	pbb, err := pTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(b[n:n+len(pbb)], pbb)
	n += len(pbb)

	// Store TTL as third TLV
	tb := make([]byte, 2)
	binary.BigEndian.PutUint16(tb, ttl)
	tTLV := &TLV{
		Type:   TLVTypeTTL,
		Length: 2,
		Value:  tb,
	}
	tbb, err := tTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(b[n:n+len(tbb)], tbb)
	n += len(tbb)

	// Store any optional TLVs
	for _, t := range f.Optional {
		tb, err := t.MarshalBinary()
		if err != nil {
			return nil, err
		}

		copy(b[n:n+len(tb)], tb)
		n += len(tb)
	}

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a Frame.
//
// If the byte slice does not contain enough data to unmarshal a valid Frame,
// io.ErrUnexpectedEOF is returned.
//
// If the four mandatory TLV values chassis ID, port ID, TTL, and end of
// LLDPDU, are missing or do not appear in order, ErrInvalidFrame is returned.
func (f *Frame) UnmarshalBinary(b []byte) error {
	// Iterate and keep creating TLVs as long as bytes remain
	var tt []*TLV
	for l := 0; len(b[l:]) > 0; {
		// Unmarshal a single TLV
		t := new(TLV)
		if err := t.UnmarshalBinary(b[l:]); err != nil {
			return err
		}

		// Advance to next TLV and keep looping
		l += 2 + int(t.Length)
		tt = append(tt, t)
	}

	// Must have at least four mandatory TLVs
	if len(tt) < 4 {
		return io.ErrUnexpectedEOF
	}

	// First TLV must be Chassis ID
	if tt[0].Type != TLVTypeChassisID {
		return ErrInvalidFrame
	}
	f.ChassisID = new(ChassisID)
	if err := f.ChassisID.UnmarshalBinary(tt[0].Value); err != nil {
		return err
	}

	// Second TLV must be Port ID
	if tt[1].Type != TLVTypePortID {
		return ErrInvalidFrame
	}
	f.PortID = new(PortID)
	if err := f.PortID.UnmarshalBinary(tt[1].Value); err != nil {
		return err
	}

	// Third TLV must be TTL and uint16 value
	if tt[2].Type != TLVTypeTTL || tt[2].Length != 2 {
		return ErrInvalidFrame
	}
	f.TTL = time.Duration(binary.BigEndian.Uint16(tt[2].Value)) * time.Second

	// Final TLV must be end of LLDPDU with length 0
	if tt[len(tt)-1].Type != TLVTypeEnd || tt[len(tt)-1].Length != 0 {
		return ErrInvalidFrame
	}

	// Optional TLVs resliced from middle
	f.Optional = tt[3 : len(tt)-1]

	return nil
}

// length calculates the number of bytes required to marshal a Frame into
// binary form.
func (f *Frame) length() int {
	// Mandatory TLVs
	var n int
	n += 2 + 1 + len(f.ChassisID.ID)
	n += 2 + 1 + len(f.PortID.ID)
	n += 2 + 2

	// Optional TLVs
	for _, t := range f.Optional {
		n += 2 + len(t.Value)
	}

	// End of LLDPDU
	n += 2

	return n
}
