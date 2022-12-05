package wifi

import (
	"fmt"
	"net"
)

type WifiInterface struct {
	Index int
	Name string
	HardwareAddr net.HardwareAddr
	Phy int
	Type InterfaceType
	Device int
	Frequency int
}

func (c *WifiInterface) String() string {
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

var WifiChannel = map[int]int {
	1: 2412,
    2: 2417,
    3: 2422,
    4: 2427,
    5: 2432,
    6: 2437,
    7: 2442,
    8: 2447,
    9: 2452,
    10: 2457,
    11: 2462,
    12: 2467,
    13: 2472,
    14: 2484,
	36: 5180,
	38: 5190,
    40: 5200,
	42: 5210,
    44: 5220,
	46: 5230,
    48: 5240,
	50: 5250,
    52: 5260,
	54: 5270,
    56: 5280,
	58: 5290,
    60: 5300,
	62: 5310,
    64: 5320,
    100: 5500,
	102: 5510,
    104: 5520,
	106: 5530,
    108: 5540,
	110: 5550,
    112: 5560,
	114: 5570,
    116: 5580,
	118: 5590,
    120: 5600,
	122: 5610,
    124: 5620,
	126: 5630,
    128: 5640,
	130: 5650,
    132: 5660,
	134: 5670,
    136: 5680,
	138: 5690,
    140: 5700,
    149: 5745,
	151: 5755,
    153: 5765,
	155: 5775,
    157: 5785,
	159: 5795,
    161: 5805,
    165: 5825,
}