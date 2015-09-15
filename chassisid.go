package lldp

import (
	"io"
)

// A ChassisIDSubtype is a value used to indicate the type of content
// carried in a ChassisID.
type ChassisIDSubtype uint8

// List of valid ChassisIDSubtype values.
const (
	ChassisIDSubtypeReserved           ChassisIDSubtype = 0
	ChassisIDSubtypeChassisComponenent ChassisIDSubtype = 1
	ChassisIDSubtypeInterfaceAlias     ChassisIDSubtype = 2
	ChassisIDSubtypePortComponent      ChassisIDSubtype = 3
	ChassisIDSubtypeMACAddress         ChassisIDSubtype = 4
	ChassisIDSubtypeNetworkAddress     ChassisIDSubtype = 5
	ChassisIDSubtypeInterfaceName      ChassisIDSubtype = 6
	ChassisIDSubtypeLocallyAssigned    ChassisIDSubtype = 7
)

// A ChassisID is a structure parsed from a chassis ID TLV.  It contains
// information which identifies a particular chassis on a given network.
type ChassisID struct {
	// Subtype specifies the type of identification carried in this ChassisID.
	Subtype ChassisIDSubtype

	// ID specifies raw bytes containing identification information for
	// this ChassisID.
	//
	// ID may carry alphanumeric data or binary data, depending upon the
	// value of Subtype.
	ID []byte
}

// MarshalBinary allocates a byte slice and marshals a ChassisID into binary
// form.
//
// MarshalBinary never returns an error.
func (c *ChassisID) MarshalBinary() ([]byte, error) {
	//  1 byte: subtype
	// N bytes: ID
	b := make([]byte, 1+len(c.ID))
	b[0] = byte(c.Subtype)
	copy(b[1:], c.ID)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a ChassisID.
//
// If the byte slice does not contain enough data to unmarshal a valid
// ChassisID, io.ErrUnexpectedEOF is returned.
func (c *ChassisID) UnmarshalBinary(b []byte) error {
	// Must indicate at least a subtype.
	if len(b) < 1 {
		return io.ErrUnexpectedEOF
	}

	c.Subtype = ChassisIDSubtype(b[0])
	c.ID = make([]byte, len(b[1:]))
	copy(c.ID, b[1:])

	return nil
}
