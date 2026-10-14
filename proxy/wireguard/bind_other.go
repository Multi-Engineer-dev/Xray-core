//go:build !linux

package wireguard

import (
	"net"

	"github.com/xtls/xray-core/features/stats"
)

// Without recvmmsg/sendmmsg x/net would send and receive one datagram per
// syscall anyway, so the bind keeps its plain path.
const batchSize = 1

func newBatchConn(net.PacketConn) (batchConn, stats.Counter, stats.Counter) {
	return nil, nil, nil
}
