package wifi

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type AttributeEncoder interface {
	EncodeAttribute(*netlink.AttributeEncoder)
}

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

func InterfaceIndexAttribute(val int) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_IFINDEX)
	return factory(uint32(val))
}

func WiphyFrequencyAttribute(val int) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_WIPHY_FREQ)
	return factory(uint32(val))
}

func InterfaceTypeAttribute(val int) *Attribute[uint32] {
	factory := NewAttributeFactory[uint32](unix.NL80211_ATTR_IFTYPE)
	return factory(uint32(val))
}

func MacAttribute(val []byte) *Attribute[[]byte] {
	factory := NewAttributeFactory[[]byte](unix.NL80211_ATTR_IFTYPE)
	return factory(val)
}