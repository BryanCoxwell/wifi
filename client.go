//go:build linux
// +build linux

package wifi

import (
	"fmt"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type Client struct {
	c             *genetlink.Conn
	familyID      uint16
	err 		  error 
}

// NewClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func NewClient() (*Client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil { return nil, fmt.Errorf("failed to open generic netlink connection: %v", err )}
	
	family, err := c.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to get nl80211 netlink family ID: %v", err)
	}
	return &Client { c: c, familyID: family.ID }, nil
}

// Close closes the client's generic netlink connection.
func (c *Client) Close() error { return c.c.Close() }

// DumpInterfaces returns a list of all wifi interfaces present on the system.
func (c *Client) DumpInterfaces() ([]*WifiInterface, error) {
	msg := newGenlMessage(unix.NL80211_CMD_GET_INTERFACE)
	ae := netlink.NewAttributeEncoder()
	flags := netlink.Request | netlink.Dump
	msg.Data = c.encodeAttributes(ae)
	c.Send(msg, flags)
	response := c.Recv()
	wifis := c.parseGetInterfaceResponse(response)
	return wifis, c.err
}

// InterfaceById returns the interface that matches the given interface index.
func (c *Client) InterfaceById(ifindex int) (*WifiInterface, error) {
	msg := newGenlMessage(unix.NL80211_CMD_GET_INTERFACE)
	ae := netlink.NewAttributeEncoder()
	AppendInterfaceIndexAttribute(ifindex, ae)
	msg.Data = c.encodeAttributes(ae)
	c.SendRequest(msg)
	response := c.Recv()
	wifis := c.parseGetInterfaceResponse(response)
	if c.err != nil { return nil, c.err }
	return wifis[0], c.err
}

// InterfaceByName takes an interface name and returns a pointer to the 
// corresponding WifiInterface
func (c *Client) InterfaceByName(name string) (*WifiInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil { return nil, fmt.Errorf("InterfaceByName: %w", err)}

	return c.InterfaceById(iface.Index)
}

// SetChannel sets the wifi channel of a given interface
func (c *Client) SetChannel(w *WifiInterface, channel int) error {
	ch, ok := WifiChannel[channel]
	if !ok { return fmt.Errorf("SetChannel: invalid channel provided: %v", channel) }

	msg := newGenlMessage(unix.NL80211_CMD_SET_WIPHY)
	ae := netlink.NewAttributeEncoder()
	AppendInterfaceIndexAttribute(w.Index, ae)	
	AppendWiphyFrequencyAttribute(ch, ae)

	msg.Data = c.encodeAttributes(ae)
	c.SendRequest(msg)
	return c.err
}

// SetInterfaceType sets the interface type of the given interface
func (c *Client) SetInterfaceType(w *WifiInterface, iftype InterfaceType) error {
	msg := newGenlMessage(unix.NL80211_CMD_SET_INTERFACE)
	ae := netlink.NewAttributeEncoder()
	AppendInterfaceIndexAttribute(w.Index, ae)
	AppendInterfaceTypeAttribute(int(iftype),  ae)
	msg.Data = c.encodeAttributes(ae)
	c.SendRequest(msg)
	return c.err
}

// newGenlMessage returns a generic netlink message with the 
// given nl80211 command set in the header.
func newGenlMessage(cmd int) *genetlink.Message {
	return &genetlink.Message {
		Header : genetlink.Header{
			Version: 1,
			Command: uint8(cmd),
		},
	}
}

// encodeAttributes takes a *netlink.AttributeEncoder as an argument
// and returns a []byte object representing the encoded data
func (c *Client) encodeAttributes(ae *netlink.AttributeEncoder) []byte {
	data, err := ae.Encode()
	if err != nil { c.err = err; return nil}
	return data
}

// Send sends a single generic netlink message
func (c *Client) Send(msg *genetlink.Message, flags netlink.HeaderFlags) {
	if c.err != nil { return }
	_, c.err = c.c.Send(*msg, c.familyID, flags)
}

// SendRequest is a convenience function for passing netlink.Request to Client.Send
func (c *Client) SendRequest(msg *genetlink.Message) {
	c.Send(msg, netlink.Request)
}

// Recv returns one or more generic netlink message responses.
func (c *Client) Recv() []genetlink.Message {
	if c.err != nil { return nil }
	msgs, _ , err := c.c.Receive()
	if err != nil { c.err = err; return nil }
	return msgs
}

// parseGetInterfaceResponse parses the responses to a NL80211_CMD_GET_INTERFACE request
func (c *Client) parseGetInterfaceResponse(msgs []genetlink.Message) []*WifiInterface {
	if c.err != nil { return nil }
	wifis := make([]*WifiInterface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil { 
			c.err = fmt.Errorf("parseGetInterfaceResponse: failed to unpack attributes: %v", err) 
			return nil
		}
		wifi := &WifiInterface{}
		for _, a := range attrs {
			switch a.Type {
			case unix.NL80211_ATTR_IFINDEX:
				wifi.Index = int(nlenc.Uint32(a.Data))
			case unix.NL80211_ATTR_IFNAME:
				wifi.Name = nlenc.String(a.Data) 
			case unix.NL80211_ATTR_MAC:
				wifi.HardwareAddr = net.HardwareAddr(a.Data)
			case unix.NL80211_ATTR_WIPHY:
				wifi.Phy = int(nlenc.Uint32(a.Data))
			case unix.NL80211_ATTR_IFTYPE:
				wifi.Type = InterfaceType(nlenc.Uint32(a.Data)) 
			case unix.NL80211_ATTR_WDEV:
				wifi.Device = int(nlenc.Uint64(a.Data))
			case unix.NL80211_ATTR_WIPHY_FREQ:
				wifi.Frequency = int(nlenc.Uint32(a.Data))
			}
		}
		wifis = append(wifis, wifi)
	}
	return wifis
}