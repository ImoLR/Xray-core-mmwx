//go:build !linux

package connection

import "fmt"

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
	return map[socketTuple]string{}, fmt.Errorf("kernel TCP state attribution is only available on Linux")
}
