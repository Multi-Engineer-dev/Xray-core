//go:build !linux

package wireguard

import (
	"net"

	"github.com/xtls/xray-core/features/stats"
)

// Without recvmmsg/sendmmsg x/net would send and receive one datagram per
// syscall anyway, so the bind keeps its plain path.
const batchSize = 1

const gsoControlSize = 0

func newBatchConn(net.PacketConn) (batchConn, bool, stats.Counter, stats.Counter) {
	return nil, false, nil, nil
}

func setGSOSize(oob []byte, _ int) []byte {
	return oob
}

func gsoFailed(error) bool {
	return false
}
