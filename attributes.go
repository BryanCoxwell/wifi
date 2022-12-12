package wifi

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type AttributeEncoder interface {
	EncodeAttribute(*netlink.AttributeEncoder)
}

// Attributes have a type (ex NL80211_ATTR_IFTYPE) and a value.
// They are encoded by passing a netlink.AttributeEncoder to their
// EncodeAttribute method.
type Attribute[T any] struct {
	typ uint16
	val T
}

func (a *Attribute[T]) EncodeAttribute(ae *netlink.AttributeEncoder){
	switch x := any(a.val).(type) {
	case uint8:
		ae.Uint8(a.typ, x)
	case uint16:
		ae.Uint16(a.typ, x)
	case uint32:
		ae.Uint32(a.typ, x)
	case uint64:
		ae.Uint64(a.typ, x)
	case string:
		ae.String(a.typ, x)
	case []byte:
		ae.Bytes(a.typ, x)
	case bool:
		ae.Flag(a.typ, x)
	case int8:
		ae.Int8(a.typ, x)
	case int16:
		ae.Int16(a.typ, x)
	case int32:
		ae.Int32(a.typ, x)
	case int64:
		ae.Int64(a.typ, x)
	}
}

// NewAttributeFactory takes an attribute type as an argument and
// returns a function which takes an attribute value and returns
// a pointer to an Attribute object
func NewAttributeFactory[T any](typ uint16) func(T)*Attribute[T]{
	return func(v T)*Attribute[T]{
		return &Attribute[T]{
			typ: typ,
			val: v,
		}
	}
}

// InterfaceIndexAttribute returns a pointer to an *Attribute[uint32]
// containing a valid NL80211_ATTR_IFINDEX value
func InterfaceIndexAttribute(val uint32) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_IFINDEX)
	return factory(uint32(val))
}

// WiphyFrequencyAttribute returns a pointer to an *Attribute[uint32]
// containing a valid NL80211_ATTR_WIPHY_FREQ value
func WiphyFrequencyAttribute(val uint32) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_WIPHY_FREQ)
	return factory(uint32(val))
}

// InterfaceTypeAttribute returns a pointer to an *Attribute[uint32]
// containing a valid NL80211_ATTR_IFTYPE value 
func InterfaceTypeAttribute(val uint32) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_IFTYPE)
	return factory(uint32(val))
}

// MacAttribute returns a pointer to an *Attribute[uint32]
// containing a valid NL80211_ATTR_MAC value
func MacAttribute(val []byte) *Attribute[[]byte] {
	factory := NewAttributeFactory[[]byte](unix.NL80211_ATTR_MAC)
	return factory(val)
}

// InterfaceNameAttribute returns a pointer to an *Attribute[string]
// containing a valid NL80211_ATTR_IFNAME value
func InterfaceNameAttribute(name string) *Attribute[string] {
	factory := NewAttributeFactory[string](unix.NL80211_ATTR_IFNAME)
	return factory(name)
}

// WiphyAttribute returns a pointer to an *Attribute[uint32]
// containing a valid NL80211_ATTR_WIPHY value
func WiphyAttribute(id uint32) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_WIPHY)
	return factory(id)
}