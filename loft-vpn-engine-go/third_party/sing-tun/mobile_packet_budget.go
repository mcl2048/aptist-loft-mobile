package tun

import (
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
	"unsafe"
)

type mobileQueuePacket struct {
	*N.PacketBuffer
	charge int
}

// Match sing's allocator buckets before allocation, including wrapper metadata.
func mobilePacketAllocation(size int) int {
	capacity := 0
	if size > 0 {
		capacity = 64
		for capacity < size && capacity < 65536 {
			capacity *= 2
		}
		if size > 65536 {
			if size <= buf.MaxPooledBufferSize {
				capacity = buf.MaxPooledBufferSize
			} else {
				capacity = size
			}
		}
	}
	return capacity + int(unsafe.Sizeof(buf.Buffer{})+unsafe.Sizeof(N.PacketBuffer{})+unsafe.Sizeof(mobileQueuePacket{}))
}

func (c *udpNatConn) releaseQueuedPacket(packet *mobileQueuePacket) {
	if c.service.packetMemoryBudget != nil {
		c.service.packetMemoryBudget.ReleasePacket(packet.charge)
	}
	N.PutPacketBuffer(packet.PacketBuffer)
}
