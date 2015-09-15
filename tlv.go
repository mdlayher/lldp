package lldp

import (
	"encoding/binary"
	"errors"
	"io"
)

// TLVLengthMax is the maximum length of value data allowed in a TLV.
const TLVLengthMax = 0x01ff

var (
	// ErrInvalidTLV is returned when a TLV is invalid due to one of the
	// following reasons:
	//  - Type is greater than TLVTypeMax
	//  - Length is greater than TLVLengthMax
	//  - Length does not match actual length of Value
	ErrInvalidTLV = errors.New("invalid TLV")
)

// A TLVType is a value used to identify the type of information carried in
// a TLV.
type TLVType uint8

// List of valid TLVType values.
const (
	// Mandatory TLVType values which must occur in all LLDPDUs.
	// TLVTypeEnd is a special sentinel value used to indicate the end of
	// TLVs in a LLDPDU.
	TLVTypeEnd       TLVType = 0
	TLVTypeChassisID TLVType = 1
	TLVTypePortID    TLVType = 2
	TLVTypeTTL       TLVType = 3

	// Optional TLVType values which may occur in LLDPDUs.
	TLVTypePortDescription    TLVType = 4
	TLVTypeSystemName         TLVType = 5
	TLVTypeSystemDescription  TLVType = 6
	TLVTypeSystemCapabilities TLVType = 7
	TLVTypeManagementAddress  TLVType = 8

	// TLVTypeOrganizationSpecific is a special TLVType which can be used
	// to carry organization-specific data in a special format.
	TLVTypeOrganizationSpecific TLVType = 127

	// TLVTypeMax is an alias for the maximum possible value for a TLVType.
	TLVTypeMax TLVType = TLVTypeOrganizationSpecific
)

// A TLV is a type-length-value structure used to carry information in an
// encoded format.
type TLV struct {
	// Type specifies the type of value carried in this TLV.
	Type TLVType

	// Length specifies the length of the value carried in this TLV.
	Length uint16

	// Value specifies the raw data carried in this TLV.
	Value []byte
}

// MarshalBinary allocates a byte slice and marshals a TLV into binary form.
//
// If Type is too large (greater than 127), Length is too large (greater than
// 511), or Length does not match the actual length of Value, ErrInvalidTLV is
// returned.
func (t *TLV) MarshalBinary() ([]byte, error) {
	// Must check upper limit for Type and Length
	if t.Type > TLVTypeMax {
		return nil, ErrInvalidTLV
	}
	if t.Length > TLVLengthMax {
		return nil, ErrInvalidTLV
	}

	// Length must match actual length of Value
	if int(t.Length) != len(t.Value) {
		return nil, ErrInvalidTLV
	}

	b := make([]byte, 2+len(t.Value))

	//  7 bits: type
	//  9 bits: length
	// N bytes: value
	var tb uint16
	tb |= uint16(t.Type) << 9
	tb |= t.Length
	binary.BigEndian.PutUint16(b[0:2], tb)
	copy(b[2:], t.Value)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a TLV.
//
// If the byte slice does not contain enough data to unmarshal a valid TLV,
// io.ErrUnexpectedEOF is returned.
func (t *TLV) UnmarshalBinary(b []byte) error {
	// Must contain type and length values
	if len(b) < 2 {
		return io.ErrUnexpectedEOF
	}

	//  7 bits: type
	//  9 bits: length
	// N bytes: value
	t.Type = TLVType(b[0]) >> 1
	t.Length = binary.BigEndian.Uint16(b[0:2]) & TLVLengthMax

	// Must contain at least enough bytes as indicated by length
	if len(b[2:]) < int(t.Length) {
		return io.ErrUnexpectedEOF
	}

	// Copy value directly into TLV
	t.Value = make([]byte, len(b[2:2+t.Length]))
	copy(t.Value, b[2:2+t.Length])

	return nil
}
