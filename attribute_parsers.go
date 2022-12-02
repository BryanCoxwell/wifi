package wifi

import (
	"bytes"
	"time"
	"unicode/utf8"
	"fmt"
	"os"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"github.com/mdlayher/netlink/nlenc"
)

// parseGetInterfaceResponse parses the responses to a 
// NL80211_CMD_GET_INTERFACE request
func parseGetInterfaceResponse(msgs []genetlink.Message) ([]*InterfaceWlanConfig, error) {
	configs := make([]*InterfaceWlanConfig, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil { return nil, fmt.Errorf("parseGetInterfaceResponse: failed to unpack attributes: %v", err)}
		config := &InterfaceWlanConfig{}
		for _, a := range attrs {
			switch a.Type {
			case unix.NL80211_ATTR_IFINDEX:
				config.Index = int(nlenc.Uint32(a.Data))
			case unix.NL80211_ATTR_IFNAME:
				config.Name = nlenc.String(a.Data) 
			case unix.NL80211_ATTR_MAC:
				config.HardwareAddr = net.HardwareAddr(a.Data)
			case unix.NL80211_ATTR_WIPHY:
				config.Phy = int(nlenc.Uint32(a.Data))
			case unix.NL80211_ATTR_IFTYPE:
				config.Type = InterfaceType(nlenc.Uint32(a.Data)) 
			case unix.NL80211_ATTR_WDEV:
				config.Device = int(nlenc.Uint64(a.Data))
			case unix.NL80211_ATTR_WIPHY_FREQ:
				config.Frequency = int(nlenc.Uint32(a.Data))
			}
		}
		configs = append(configs, config)
	}
	return configs, nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil { return nil, fmt.Errorf("failed to unmarshal attributes: %v", err) }

		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil { return nil, fmt.Errorf("failed to unmarshal attributes: %v", err) }

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				continue
			}

			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil { return nil, fmt.Errorf("failed to parse attributes: %v", err) }

			return &bss, nil
		}
	}

	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_BSS_BSSID:
			b.BSSID = net.HardwareAddr(a.Data)
		case unix.NL80211_BSS_FREQUENCY:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_BEACON_INTERVAL:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case unix.NL80211_BSS_SEEN_MS_AGO:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_BSS_STATUS:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_INFORMATION_ELEMENTS:
			ies, err := parseIEs(a.Data)
			if err != nil { return fmt.Errorf("failed to parse IEs: %v", err) }

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				}
			}
		}
	}
	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil { return nil, fmt.Errorf("failed to unmarshal attributes: %v", err) }

	var info StationInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_MAC:
			info.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_STA_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil { return nil, fmt.Errorf("failed to unmarshal attributes: %v", err) }

			if err := (&info).parseAttributes(nattrs); err != nil { return nil, fmt.Errorf("failed to parse attributes") }

			return &info, nil
		}
	}
	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_STA_INFO_CONNECTED_TIME:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case unix.NL80211_STA_INFO_INACTIVE_TIME:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_STA_INFO_RX_BYTES64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_TX_BYTES64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_SIGNAL:
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			// Should just be cast to int8, see code here: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c#n378
			info.Signal = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_RX_PACKETS:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_PACKETS:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_RETRIES:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_FAILED:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_BEACON_LOSS:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_RX_BITRATE, unix.NL80211_STA_INFO_TX_BITRATE:
			bitrate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case unix.NL80211_STA_INFO_RX_BITRATE:
				info.ReceiveBitrate = bitrate
			case unix.NL80211_STA_INFO_TX_BITRATE:
				info.TransmitBitrate = bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == unix.NL80211_STA_INFO_RX_BYTES {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == unix.NL80211_STA_INFO_TX_BYTES {
			info.TransmittedBytes = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// parseRateInfo parses a bitrate from netlink attributes.
func parseRateInfo(b []byte) (int, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil { return 0, fmt.Errorf("parseRateInfo: failed to unmarshal attributes: %v", err) }
	var bitrate int
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_RATE_INFO_BITRATE32:
			bitrate = int(nlenc.Uint32(a.Data))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if bitrate == 0 && a.Type == unix.NL80211_RATE_INFO_BITRATE {
			bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	bitrate *= 100000
	return bitrate, nil
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		buf.WriteRune(r)
	}
	return buf.String()
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}
	return false
}

type AttrEncoderFunc func(ae *netlink.AttributeEncoder)

// i32AttributeEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided attrType and attrVal when called
func i32AttributeEncoder(attrType int, attrVal int) AttrEncoderFunc {
	var encoderFunc = func(ae *netlink.AttributeEncoder) {
		ae.Int32(uint16(attrType), int32(attrVal))
	}
	return encoderFunc
}

// bytesAttributeEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided attrType and attrVal when called
func bytesAttributeEncoder(attrType int, attrVal []byte) AttrEncoderFunc {
	var encoderFunc = func(ae *netlink.AttributeEncoder) {
		ae.Bytes(uint16(attrType), attrVal)
	}
	return encoderFunc
}

// channelWidthEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided channel width when called
func channelWidthEncoder(w int) AttrEncoderFunc {
	var encoderFunc = i32AttributeEncoder(unix.NL80211_ATTR_CHANNEL_WIDTH, w)
	return encoderFunc
}

// iftypeEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided iftype as an integer when called
func iftypeEncoder(iftype InterfaceType) AttrEncoderFunc {
	var encoderFunc = i32AttributeEncoder(unix.NL80211_ATTR_IFTYPE, int(iftype))
	return encoderFunc
}

// ifindexEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided ifindex as an integer when called
func ifindexEncoder(ifindex int) AttrEncoderFunc {
	var encoderFunc = i32AttributeEncoder(unix.NL80211_ATTR_IFINDEX, ifindex)
	return encoderFunc
}

// wiphyFreqEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided frequency as an integer when called
func wiphyFreqEncoder(freq int) AttrEncoderFunc {
	var encoderFunc = i32AttributeEncoder(unix.NL80211_ATTR_WIPHY_FREQ, freq)
	return encoderFunc
}

// hardwareAddrEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument which encodes the provided MAC address when called
func hardwareAddrEncoder(mac net.HardwareAddr) AttrEncoderFunc {
	if mac == nil { return nil}
	var encoderFunc = bytesAttributeEncoder(unix.NL80211_ATTR_MAC, mac)
	return encoderFunc
}

// connectionAttrEncoder returns a function that takes a *netlink.AttributeEncoder
// object as an argument and, when called, encodes the necessary attributes
// to satisfy the NL80211_CMD_CONNECT command.
// For open networks pass an empty string for the psk argument.
func connectionAttrEncoder(ssid, psk string) AttrEncoderFunc {
	const cipherSuites = 0xfac04
	const akmSuites    = 0xfac02

	var encoderFunc = func(ae *netlink.AttributeEncoder) {
		ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
		if psk != "" {
			ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
			ae.Flag(unix.NL80211_ATTR_WANT_1X_4WAY_HS, true)
			ae.Bytes(
				unix.NL80211_ATTR_PMK,
				wpaPassphrase([]byte(ssid), []byte(psk)),
			)
		}
		ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
	}
	return encoderFunc
}