//go:build linux

package connection

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	tcpEstablishedState = "01"
	tcpSynSentState     = "02"
	tcpSynRecvState     = "03"
	tcpFinWait1State    = "04"
	tcpFinWait2State    = "05"
	tcpTimeWaitState    = "06"
	tcpCloseState       = "07"
	tcpCloseWaitState   = "08"
	tcpLastAckState     = "09"
	tcpListenState      = "0A"
	tcpClosingState     = "0B"
	tcpNewSynRecvState  = "0C"
)

func readKernelTCPSockets() (map[socketTuple]string, error) {
	result := make(map[socketTuple]string)
	readable := 0
	for _, source := range []struct {
		path string
		ipv6 bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		file, err := os.Open(source.path)
		if err != nil {
			continue
		}
		err = parseProcTCP(file, source.ipv6, result)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source.path, err)
		}
		readable++
	}
	if readable == 0 {
		return nil, fmt.Errorf("no /proc/net TCP tables are readable")
	}
	return result, nil
}

func parseProcTCP(reader io.Reader, ipv6 bool, result map[socketTuple]string) error {
	scanner := bufio.NewScanner(reader)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localIP, localPort, err := parseProcAddr(fields[1], ipv6)
		if err != nil {
			return err
		}
		remoteIP, remotePort, err := parseProcAddr(fields[2], ipv6)
		if err != nil {
			return err
		}
		result[socketTuple{LocalIP: localIP.Unmap(), LocalPort: localPort, RemoteIP: remoteIP.Unmap(), RemotePort: remotePort}] = strings.ToUpper(fields[3])
	}
	return scanner.Err()
}

func parseProcAddr(value string, ipv6 bool) (netip.Addr, uint16, error) {
	rawIP, rawPort, ok := strings.Cut(value, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("invalid socket address %q", value)
	}
	port, err := strconv.ParseUint(rawPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	decoded, err := hex.DecodeString(rawIP)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if ipv6 {
		if len(decoded) != 16 {
			return netip.Addr{}, 0, fmt.Errorf("invalid IPv6 address %q", rawIP)
		}
		for offset := 0; offset < len(decoded); offset += 4 {
			reverseProcBytes(decoded[offset : offset+4])
		}
		var bytes [16]byte
		copy(bytes[:], decoded)
		return netip.AddrFrom16(bytes).Unmap(), uint16(port), nil
	}
	if len(decoded) != 4 {
		return netip.Addr{}, 0, fmt.Errorf("invalid IPv4 address %q", rawIP)
	}
	reverseProcBytes(decoded)
	var bytes [4]byte
	copy(bytes[:], decoded)
	return netip.AddrFrom4(bytes), uint16(port), nil
}

func reverseProcBytes(value []byte) {
	for left, right := 0, len(value)-1; left < right; left, right = left+1, right-1 {
		value[left], value[right] = value[right], value[left]
	}
}
