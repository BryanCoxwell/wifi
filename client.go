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
}

// NewClient opens a generic netlink connection and sets the nl80211 family ID
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
	msg, err := NewNl80211Message(unix.NL80211_CMD_GET_INTERFACE, nil)
	if err != nil { return nil, fmt.Errorf("DumpInterfaces: %v", err)}
	
	request := &Nl80211Request{
		RequestMessage: msg,
		Flags: netlink.Request | netlink.Dump,
	}

	response, err := request.Response(c)
	if err != nil { return nil, fmt.Errorf("DumpInterfaces: %v", err)}

	return c.parseGetInterfaceResponse(response)
}

// InterfaceById returns the interface that matches the given interface index.
func (c *Client) InterfaceById(ifindex int) (*WifiInterface, error) {
	attrs := []AttributeEncoder{
		InterfaceIndexAttribute(ifindex),
	}
	msg, err := NewNl80211Message(unix.NL80211_CMD_GET_INTERFACE, attrs)
	if err != nil { return nil, fmt.Errorf("InterfaceById: %v", err)}

	request := &Nl80211Request{
		RequestMessage: msg,
		Flags: netlink.Request,
	}
	
	response, err := request.Response(c)
	if err != nil { return nil, fmt.Errorf("InterfaceById: %v", err)}

	wifis, err := c.parseGetInterfaceResponse(response)
	if err != nil { return nil, fmt.Errorf("InterfaceById: %v", err)}

	return wifis[0], nil
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

	attrs := []AttributeEncoder{
		InterfaceIndexAttribute(w.Index),
		WiphyFrequencyAttribute(ch),
	}

	msg, err := NewNl80211Message(unix.NL80211_CMD_SET_WIPHY, attrs)
	if err != nil {return fmt.Errorf("SetChannel: %v", err)}

	request := &Nl80211Request{
		RequestMessage: msg,
		Flags: netlink.Request | netlink.Acknowledge,
	}

	_, err = request.Response(c)
	return err
}

// SetInterfaceType sets the interface type of the given interface
func (c *Client) SetInterfaceType(w *WifiInterface, iftype InterfaceType) error {
	attrs := []AttributeEncoder{
		InterfaceIndexAttribute(w.Index),
		InterfaceTypeAttribute(int(iftype)),
	}
	msg, err := NewNl80211Message(unix.NL80211_CMD_SET_INTERFACE, attrs)
	if err != nil { return fmt.Errorf("SetInterfaceType: %v", err)}

	request := &Nl80211Request{
		RequestMessage: msg,
		Flags: netlink.Request | netlink.Acknowledge,
	}
	_, err = request.Response(c)
	return err
}

// parseGetInterfaceResponse parses the responses to a NL80211_CMD_GET_INTERFACE request
func (c *Client) parseGetInterfaceResponse(msgs []genetlink.Message) ([]*WifiInterface, error) {
	wifis := make([]*WifiInterface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil { 
			return nil, fmt.Errorf("parseGetInterfaceResponse: failed to unpack attributes: %v", err) 
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
	return wifis, nil
}

// NewNl80211Message takes a command and a list of attributes and returns 
// a generic netlink message containing the encoded attributes. 
func NewNl80211Message(cmd int, lst []AttributeEncoder) (*genetlink.Message, error) {
	msg := &genetlink.Message {
		Header: genetlink.Header{
			Version: 1,
			Command: uint8(cmd),
		},
	}

	ae := netlink.NewAttributeEncoder()
	for _, a := range lst {
		a.EncodeAttribute(ae)
	}
	data, err := ae.Encode()
	if err != nil { return nil, fmt.Errorf("NewNl80211Message") }

	msg.Data = data
	return msg, nil
}

type Nl80211Request struct {
	RequestMessage *genetlink.Message
	Flags netlink.HeaderFlags
	err error
}

// Response sends a Netlink request and returns a list of generic
// netlink messages (the response)
func (r Nl80211Request) Response(c *Client) ([]genetlink.Message, error){
	if r.err != nil { return nil, r.err }

	_, err := c.c.Send(*r.RequestMessage, c.familyID, r.Flags)
	if err != nil { return nil, fmt.Errorf("Response: %v", err) }

	msgs, nlmsgs, err := c.c.Receive()
	if err != nil { return nil, fmt.Errorf("Response: %v", err) }

	// At this point, since err is nil we should be able to assume
	// any message of type Error is an ACK response and drop it.
	if nlmsgs[0].Header.Type == netlink.Error {
		return msgs[1:], nil
	}

	return msgs, nil
}
