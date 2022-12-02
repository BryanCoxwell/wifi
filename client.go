//go:build linux
// +build linux

package wifi

import (
	"crypto/sha1"
	"fmt"
	"net"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/unix"
)

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type Client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8
}

// NewClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func NewClient() (*Client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("NewClient: failed to create generic netlink connection: %v", err)
	}

	// Make a best effort to apply the strict options set to provide better
	// errors and validation. We don't apply Strict in the constructor because
	// this library is widely used on a range of kernels and we can't guarantee
	// it will always work on older kernels.
	// for _, o := range []netlink.ConnOption{
	// 	netlink.ExtendedAcknowledge,
	// 	netlink.GetStrictCheck,
	// } {
	// 	_ = c.SetOption(o, true)
	// }
	family, err := c.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("initClient: failed to get nl80211 family id: %v", err)
	}
	return &Client {
		c:				c,
		familyID:   	family.ID,
		familyVersion: 	family.Version,
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *Client) Close() error { return c.c.Close() }

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *Client) Interfaces() ([]*WifiInterface, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		netlink.Dump,
		nil,
		nil,
	)
	if err != nil { return nil, fmt.Errorf("Interfaces: failed to get interfaces: %v", err) }

	interfaceWlanConfigs, err := parseGetInterfaceResponse(msgs)
	if err != nil { return nil, fmt.Errorf("Interfaces: failed to parse response messages: %v", err )}
	
	wifis := make([]*WifiInterface, len(interfaceWlanConfigs))
	for idx, i := range interfaceWlanConfigs {
		net_ifi, err := net.InterfaceByIndex(i.Index)
		if err != nil { return nil, fmt.Errorf("Interfaces: failed to find interface with index %v: %v", i.Index, err)}
		wifis[idx] = (*WifiInterface)(net_ifi)
	}
	return wifis, nil
}

// InterfaceByName calls Interfaces() and returns one interface or nil 
// if the requested interface doesn't exist. 
func (c *Client) InterfaceByName(name string) (*WifiInterface, error) {
	interfaces, err := c.Interfaces()

	if err != nil { return nil, fmt.Errorf("InterfaceByName: %w", err) }
	for _, i := range interfaces {
		if i.Name == name { return i, nil }
	}
	return nil, nil
}

// Connect starts connecting the interface to the specified ssid.
// Pass an empty string to psk to connect to an open network.
func (c *Client) Connect(w *WifiInterface, ssid, psk string) error {
	_, err := c.get(
		unix.NL80211_CMD_CONNECT,
		0,
		w,
		connectionAttrEncoder(ssid, psk),
	)
	return err
}

// Disconnect disconnects the interface.
func (c *Client) Disconnect(w *WifiInterface) error {
	_, err := c.get(
		unix.NL80211_CMD_DISCONNECT,
		0,
		w,
		nil,
	)
	return err
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *Client) BSS(w *WifiInterface) (*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		w,
		hardwareAddrEncoder(w.HardwareAddr),
	)
	if err != nil { return nil, fmt.Errorf("BSS: failed to get the BSS for interface %v: %v", w.Name, err) }
	return parseBSS(msgs)
}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *Client) StationInfo(w *WifiInterface) ([]*StationInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_STATION,
		netlink.Dump,
		w,
		hardwareAddrEncoder(w.HardwareAddr),
	)
	if err != nil { return nil, err }
	if len(msgs) == 0 { return nil, os.ErrNotExist }
	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if stations[i], err = parseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}
	return stations, nil
}

// SetFrequency sets the frequency of a wireless interface.
// Does nothing if frequency is already passed in value.
func (c *Client) SetFrequency(w *WifiInterface, freq int) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_WIPHY,
		netlink.Acknowledge,	
		w,
		wiphyFreqEncoder(freq),
	)
	return err
}

// SetChannelWidth sets the channel of a wireless interface.
func (c *Client) SetChannelWidth(w *WifiInterface, width int) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_WIPHY,
		0,
		w,
		channelWidthEncoder(width),
	)
	return err
}

// SetInterfaceType sets the WifiInterface's type, eg monitor/station/etc.
func (c *Client) SetInterfaceType(w *WifiInterface, iftype InterfaceType) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_INTERFACE,
		netlink.Acknowledge,
		w,
		iftypeEncoder(iftype),
	)
	if err != nil { return fmt.Errorf("SetInterfaceType: %w", err)}
	return nil	
}

// InterfaceWlanConfig returns an interfaceWlanConfig object for a given interface
func (c *Client) InterfaceWlanConfig(w *WifiInterface) (*InterfaceWlanConfig, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		0,
		w,
		ifindexEncoder(w.Index),
	)
	if err != nil { return nil, fmt.Errorf("InterfaceWlanConfig: failed to get interface with index %v: %v", w.Index, err) }

	wlan_configs, err := parseGetInterfaceResponse(msgs)	
	if err != nil { return nil, fmt.Errorf("InterfaceWlanConfig: failed to parse response messages: %v", err)}
	
	return wlan_configs[0], nil
}

// InterfaceFrequency returns the frequency of the given interface
func (c *Client) InterfaceFrequency(w *WifiInterface) (int, error) {
	config, err := c.InterfaceWlanConfig(w)
	if err != nil { return -1, fmt.Errorf("InterfaceFrequency: %w", err)}
	return config.Frequency, nil
}

// InterfaceType returns the type of the given interface
func (c *Client) InterfaceType(w *WifiInterface) (InterfaceType, error) {
	config, err := c.InterfaceWlanConfig(w)
	if err != nil { return -1, fmt.Errorf("InterfaceType: %w", err)}
	return config.Type, nil
}

// InterfacePhy returns the PHY index of the given interface
func (c *Client) InterfacePhy(w *WifiInterface) (int, error) {
	config, err := c.InterfaceWlanConfig(w)
	if err != nil { return -1, fmt.Errorf("InterfacePhy: %w", err)}
	return config.Phy, nil
}

// get performs a request/response interaction with nl80211.
func (c *Client) get(
	cmd uint8,
	flags netlink.HeaderFlags,
	w *WifiInterface,
	// May be nil; used to apply optional parameters.
	params func(ae *netlink.AttributeEncoder),
) ([]genetlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	w.encode(ae)
	if params != nil {
		// Optionally apply more parameters to the attribute encoder.
		params(ae)
	}
	b, err := ae.Encode()
	_, err = c.c.Send(
		genetlink.Message{
			Header: genetlink.Header{
				Command: cmd,
				Version: c.familyVersion,
			},
			Data: b,
		},
		// Always pass the genetlink family ID and request flag.
		c.familyID,
		netlink.Request|flags,
	)
	msgs, _, err := c.c.Receive()
	return msgs, err
}

// wpaPassphrase computes a WPA passphrase given an SSID and preshared key.
func wpaPassphrase(ssid, psk []byte) []byte {
	return pbkdf2.Key(psk, ssid, 4096, 32, sha1.New)
}