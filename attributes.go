package wifi

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

/* 
The below factory functions allow for easily creating functions that take only an attribute
value and a *netlink.AttributeEncoder as arguments. I've found this helps to increase the 
readibility of the functions that handle creating and sending NL80211 command messages.

They are used to make attribute encoder functions eg:

var AppendInterfaceIndexAttribute = uint32AttrEncoderFactory(unix.NL80211_ATTR_IFINDEX)

which can be used with a *netlink.AttributeEncoder as:

ae := netlink.NewAttributeEncoder()
AppendInterfaceIndexAttribute(1, ae)
encodedAttrs, err := ae.Encode()

More attribute encoder functions like AppendInterfaceIndexAttribute are defined for some
(not all, yet) NL80211 attributes below.
*/

// int8AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Int8 method to the attribute type and attribute value.
func int8AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Int8(uint16(attributeType), int8(v))
	}
	return encoderFunc
}

// int16AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Int16 method to the attribute type and attribute value.
func int16AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Int16(uint16(attributeType), int16(v))
	}
	return encoderFunc
}

// int32AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Int32 method to the attribute type and attribute value.
func int32AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Int32(uint16(attributeType), int32(v))
	}
	return encoderFunc
}

// int64AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Int64 method to the attribute type and attribute value.
func int64AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Int64(uint16(attributeType), int64(v))
	}
	return encoderFunc
}

// uint8AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Uint8 method to the attribute type and attribute value.
func uint8AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Uint8(uint16(attributeType), uint8(v))
	}
	return encoderFunc
}

// uint16AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Uint16 method to the attribute type and attribute value.
func uint16AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Uint16(uint16(attributeType), uint16(v))
	}
	return encoderFunc
}

// uint32AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Uint32 method to the attribute type and attribute value.
func uint32AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Uint32(uint16(attributeType), uint32(v))
	}
	return encoderFunc
}

// uint64AttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Uint64 method to the attribute type and attribute value.
func uint64AttrEncoderFactory(attributeType int) func(int, *netlink.AttributeEncoder) {
	encoderFunc := func(v int, ae *netlink.AttributeEncoder) {
		ae.Uint64(uint16(attributeType), uint64(v))
	}
	return encoderFunc
}

// stringAttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// String method to the attribute type and attribute value.
func stringAttrEncoderFactory(attributeType int) func(string, *netlink.AttributeEncoder) {
	encoderFunc := func(v string, ae *netlink.AttributeEncoder) {
		ae.String(uint16(attributeType), v)
	}
	return encoderFunc
}

// bytesAttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Bytes method to the attribute type and attribute value.
func bytesAttrEncoderFactory(attributeType int) func([]byte, *netlink.AttributeEncoder) {
	encoderFunc := func(v []byte, ae *netlink.AttributeEncoder) {
		ae.Bytes(uint16(attributeType), v)
	}
	return encoderFunc
}

// flagAttrEncoderFactory takes an attribute type as an argument and returns a function
// that takes the corresponding attribute type's value and a *netlink.AttributeEncoder
// as arguments. The resulting function returns no value but applies the *netlink.AttributeEncoder's
// Flag method to the attribute type and attribute value.
func flagAttrEncoderFactory(attributeType int) func(bool, *netlink.AttributeEncoder) {
	encoderFunc := func(v bool, ae *netlink.AttributeEncoder) {
		ae.Flag(uint16(attributeType), v)
	}
	return encoderFunc
}

// AppendInterfaceIndexAttribute takes an interface index and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given interface index.
var AppendInterfaceIndexAttribute		= uint32AttrEncoderFactory(unix.NL80211_ATTR_IFINDEX)

// AppendInterfaceTypeAttribute takes an interface type and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given interface type.
var AppendInterfaceTypeAttribute 		= uint32AttrEncoderFactory(unix.NL80211_ATTR_IFTYPE)

// AppendWiphyFrequencyAttribute takes a wifi frequency and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given wifi frequency.
var AppendWiphyFrequencyAttribute 		= uint32AttrEncoderFactory(unix.NL80211_ATTR_WIPHY_FREQ)

// AppendMacAttribute takes a MAC address and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Bytes method on the given MAC address
var AppendMacAttribute					= bytesAttrEncoderFactory(unix.NL80211_ATTR_MAC)

// AppendWpaVersionsAttribute takes a WPA version and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given WPA version.
var AppendWpaVersionsAttribute 			= uint32AttrEncoderFactory(unix.NL80211_ATTR_WPA_VERSIONS)

// AppendCipherSuiteGroupAttribute takes a cipher suite group (integer) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given cipher suite group value.
var AppendCipherSuiteGroupAttribute 	= uint32AttrEncoderFactory(unix.NL80211_ATTR_CIPHER_SUITE_GROUP)

// AppendCipherSuitesPairwiseAttribute takes a cipher suite pairwise value (integer) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given cipher suite pairwise value.
var AppendCipherSuitesPairwiseAttribute = uint32AttrEncoderFactory(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE)

// AppendAkmSuitesAttribute takes an AKM suite value (integer) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given AKM suite value.
var AppendAkmSuitesAttribute 			= uint32AttrEncoderFactory(unix.NL80211_ATTR_AKM_SUITES)

// AppendWant1x4WayAttribute takes a Want1x4Way attribute (bool) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Flag method on the given Want1x4Way value
var AppendWant1x4WayAttribute 			= flagAttrEncoderFactory(unix.NL80211_ATTR_WANT_1X_4WAY_HS)

// AppendPmkAttribute takes a PMK value ([]byte) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Bytes method on the given PMK value
var AppendPmkAttribute					= bytesAttrEncoderFactory(unix.NL80211_ATTR_PMK)

// AppendSsidAttribute takes an SSID value and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Bytes method on the given SSID.
var AppendSsidAttribute 				= bytesAttrEncoderFactory(unix.NL80211_ATTR_SSID)

// AppendAuthTypeAttribute takes an auth type value (integer) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given auth type
var AppendAuthTypeAttribute				= uint32AttrEncoderFactory(unix.NL80211_ATTR_AUTH_TYPE)

// AppendChannelWidthAttribute takes a channel width (integer) and a *netlink.AttributeEncoder
// as arguments and calls AttributeEncoder's Uint32 method on the given channel width
var AppendChannelWidthAttribute			= uint32AttrEncoderFactory(unix.NL80211_ATTR_CHANNEL_WIDTH)
