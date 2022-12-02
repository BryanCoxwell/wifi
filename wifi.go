package wifi

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
	"github.com/mdlayher/netlink"
)

type WifiInterface net.Interface

type InterfaceWlanConfig struct {
	Index int
	Name string
	HardwareAddr net.HardwareAddr
	Phy int
	Type InterfaceType
	Device int
	Frequency int
}

// encode provides an encoding function for ifi's attributes. If ifi is nil,
// encode is a no-op.
func (w *WifiInterface) encode(ae *netlink.AttributeEncoder) {
	if w == nil { return }
	// Mandatory.
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(w.Index))
}

func (w *WifiInterface) String() string {
	return fmt.Sprintf("<WifiInterface: Index=%v, Name=%v, MTU=%v, HardwareAddr=%v, Flags=%v", w.Index, w.Name, w.MTU, w.HardwareAddr, w.Flags)
}

func (c *InterfaceWlanConfig) String() string {
	return fmt.Sprintf("<InterfaceWlanConfig: Index=%v, Name=%v, HardwareAddr=%v, Phy=%v, Type=%v, Device=%v, Frequency=%v", c.Index, c.Name, c.HardwareAddr, c.Phy, c.Type, c.Device, c.Frequency)
}

// An InterfaceType is the operating mode of an Interface.
type InterfaceType int

const (
	InterfaceTypeUnspecified InterfaceType = iota
	InterfaceTypeAdHoc
	InterfaceTypeStation
	InterfaceTypeAP
	InterfaceTypeAPVLAN
	InterfaceTypeWDS
	InterfaceTypeMonitor
	InterfaceTypeMeshPoint
	InterfaceTypeP2PClient
	InterfaceTypeP2PGroupOwner
	InterfaceTypeP2PDevice
	InterfaceTypeOCB
	InterfaceTypeNAN
)

// String returns the string representation of an InterfaceType.
func (t InterfaceType) String() string {
	switch t {
	case InterfaceTypeUnspecified:
		return "unspecified"
	case InterfaceTypeAdHoc:
		return "ad-hoc"
	case InterfaceTypeStation:
		return "station"
	case InterfaceTypeAP:
		return "access point"
	case InterfaceTypeWDS:
		return "wireless distribution"
	case InterfaceTypeMonitor:
		return "monitor"
	case InterfaceTypeMeshPoint:
		return "mesh point"
	case InterfaceTypeP2PClient:
		return "P2P client"
	case InterfaceTypeP2PGroupOwner:
		return "P2P group owner"
	case InterfaceTypeP2PDevice:
		return "P2P device"
	case InterfaceTypeOCB:
		return "outside context of BSS"
	case InterfaceTypeNAN:
		return "near-me area network"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// StationInfo contains statistics about a WiFi interface operating in
// station mode.
type StationInfo struct {
	HardwareAddr net.HardwareAddr
	Connected time.Duration
	Inactive time.Duration
	ReceivedBytes int
	TransmittedBytes int
	ReceivedPackets int
	TransmittedPackets int
	ReceiveBitrate int
	TransmitBitrate int
	Signal int
	TransmitRetries int
	TransmitFailed int
	BeaconLoss int
}

// A BSS is an 802.11 basic service set.  It contains information about a wireless
// network associated with an Interface.
type BSS struct {
	SSID string
	BSSID net.HardwareAddr
	Frequency int
	BeaconInterval time.Duration
	LastSeen time.Duration
	Status BSSStatus
}

// A BSSStatus indicates the current status of client within a BSS.
type BSSStatus int

const (
	BSSStatusAuthenticated BSSStatus = iota
	BSSStatusAssociated
	BSSStatusIBSSJoined
)

// String returns the string representation of a BSSStatus.
func (s BSSStatus) String() string {
	switch s {
	case BSSStatusAuthenticated:
		return "authenticated"
	case BSSStatusAssociated:
		return "associated"
	case BSSStatusIBSSJoined:
		return "IBSS joined"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// errInvalidIE is returned when one or more IEs are malformed.
var errInvalidIE = errors.New("invalid 802.11 information element")

// List of 802.11 Information Element types.
const (
	ieSSID = 0
)

// An ie is an 802.11 information element.
type ie struct {
	ID uint8
	// Length field implied by length of data
	Data []byte
}

// parseIEs parses zero or more ies from a byte slice.
// Reference:
// https://www.safaribooksonline.com/library/view/80211-wireless-networks/0596100523/ch04.html#wireless802dot112-CHP-4-FIG-31
func parseIEs(b []byte) ([]ie, error) {
	var ies []ie
	var i int
	for {
		if len(b[i:]) == 0 {
			break
		}
		if len(b[i:]) < 2 {
			return nil, errInvalidIE
		}

		id := b[i]
		i++
		l := int(b[i])
		i++

		if len(b[i:]) < l {
			return nil, errInvalidIE
		}

		ies = append(ies, ie{
			ID:   id,
			Data: b[i : i+l],
		})

		i += l
	}

	return ies, nil
}
