package wifi_test

import (
	"fmt"
	"testing"

	"github.com/bryancoxwell/wifi"
	"github.com/mdlayher/genetlink"
	"golang.org/x/sys/unix"
)

var _, _ = fmt.Println("Testing: Client.go")


func comparePackets(expected, actual genetlink.Message) bool {
	if expected.Header != actual.Header {
		return false
	}
	if len(expected.Data) != len(actual.Data) {
		return false
	}
	for idx, i := range expected.Data {
		if actual.Data[idx] != i {
			return false
		}
	}
	return true
}

var packetMismatchMessage = "\nGenerated packet doesn't match expected output.\nExpected: \t%v\nGot:\t\t%v\n"

// TestNewNl80211MessageGetInterfaceWithAttribute tests the NewNl80211Message function from the wifi package.
// The function should return the correct genetlink.Message with the given interface index attribute.
func TestNewNl80211MessageGetInterfaceWithAttribute(t *testing.T) {
	expectedMessage := genetlink.Message {
		Header: genetlink.Header{
			Version: 1,
			Command: 5,
		},
		Data: []byte{8, 0, 3, 0, 3, 0, 0, 0},
	}

    var ifindex uint32 = 3
	attrs := []wifi.AttributeEncoder{
		wifi.InterfaceIndexAttribute(ifindex),
	}
	msg, _ := wifi.NewNl80211Message(unix.NL80211_CMD_GET_INTERFACE, attrs)
    if !comparePackets(expectedMessage, *msg) {
        t.Errorf(packetMismatchMessage, expectedMessage, *msg)
    }
	
}

// TestNewNl80211MessageGetInterfaceNoAttribute tests the NewNl80211Message function from the wifi package.
// The function should return the correct genetlink.Message with no attributes passed to it.
func TestNewNl80211MessageGetInterfaceNoAttribute(t *testing.T) {
	expectedMessage := genetlink.Message {
		Header: genetlink.Header{
			Version: 1,
			Command: 5,
		},
	}

	msg, _ := wifi.NewNl80211Message(unix.NL80211_CMD_GET_INTERFACE, nil)
    if !comparePackets(expectedMessage, *msg) {
        t.Errorf(packetMismatchMessage, expectedMessage, *msg)
    }
}

// TestNewNl80211MessageSetChannel tests the NewNl80211Message function from the wifi package.
// The function should return the correct genetlink.Message with the given interface index and channel.
func TestNewNl80211MessageSetChannel(t *testing.T) {
	expectedMessage := genetlink.Message {
		Header: genetlink.Header{
			Version: 1,
			Command: 2,
		},
		Data: []byte{8, 0, 3, 0, 5, 0, 0, 0, 8, 0, 38, 0, 11, 0, 0, 0},
	}

	ifindex := uint32(5)
	channel := uint32(11)
	attrs := []wifi.AttributeEncoder{
		wifi.InterfaceIndexAttribute(ifindex),
		wifi.WiphyFrequencyAttribute(channel),
	}

	msg, _ := wifi.NewNl80211Message(unix.NL80211_CMD_SET_WIPHY, attrs)
	if !comparePackets(expectedMessage, *msg){
		t.Errorf(packetMismatchMessage, expectedMessage, *msg)
	}
}

// TestNewNl80211MessageSetInterface tests the NewNl80211Message function from the wifi package.
// The function should return the correct genetlink.Message with the given interface index and interface type.
func TestNewNl80211MessageSetInterface(t *testing.T) {
	expectedMessage := genetlink.Message {
		Header: genetlink.Header{
			Version: 1,
			Command: 6,
		},
		Data: []byte{8, 0, 3, 0, 6, 0, 0, 0, 8, 0, 5, 0, 6, 0, 0, 0},
	}

	ifindex := uint32(6)
	iftype := unix.NL80211_IFTYPE_MONITOR
	attrs := []wifi.AttributeEncoder{
		wifi.InterfaceIndexAttribute(ifindex),
		wifi.InterfaceTypeAttribute(uint32(iftype)),
	}
	msg, _ := wifi.NewNl80211Message(unix.NL80211_CMD_SET_INTERFACE, attrs)
	if !comparePackets(expectedMessage, *msg) {
		t.Errorf(packetMismatchMessage, expectedMessage, *msg)
	}
}
