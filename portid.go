package lldp

import (
	"io"
)

// A PortIDSubtype is a value used to indicate the type of content
// carried in a PortID.
type PortIDSubtype uint8

// List of valid PortIDSubtype values.
const (
	PortIDSubtypeReserved        PortIDSubtype = 0
	PortIDSubtypeInterfaceAlias  PortIDSubtype = 1
	PortIDSubtypePortComponent   PortIDSubtype = 2
	PortIDSubtypeMACAddress      PortIDSubtype = 3
	PortIDSubtypeNetworkAddress  PortIDSubtype = 4
	PortIDSubtypeInterfaceName   PortIDSubtype = 5
	PortIDSubtypeAgentCircuitID  PortIDSubtype = 6
	PortIDSubtypeLocallyAssigned PortIDSubtype = 7
)

// A PortID is a structure parsed from a port ID TLV.  It contains
// information which identifies a particular chassis on a given network.
type PortID struct {
	// Subtype specifies the type of identification carried in this PortID.
	Subtype PortIDSubtype

	// ID specifies raw bytes containing identification information for
	// this PortID.
	//
	// ID may carry alphanumeric data or binary data, depending upon the
	// value of Subtype.
	ID []byte
}

// MarshalBinary allocates a byte slice and marshals a PortID into binary
// form.
//
// MarshalBinary never returns an error.
func (p *PortID) MarshalBinary() ([]byte, error) {
	//  1 byte: subtype
	// N bytes: ID
	b := make([]byte, 1+len(p.ID))
	b[0] = byte(p.Subtype)
	copy(b[1:], p.ID)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a PortID.
//
// If the byte slice does not contain enough data to unmarshal a valid
// PortID, io.ErrUnexpectedEOF is returned.
func (p *PortID) UnmarshalBinary(b []byte) error {
	// Must indicate at least a subtype.
	if len(b) < 1 {
		return io.ErrUnexpectedEOF
	}

	p.Subtype = PortIDSubtype(b[0])
	p.ID = make([]byte, len(b[1:]))
	copy(p.ID, b[1:])

	return nil
}
