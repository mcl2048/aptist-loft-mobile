package vpn

import (
	"context"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type queueHandler struct{ connections chan N.PacketConn }

func (h *queueHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections <- conn
}

type discardWriter struct{}

func (discardWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func newQueue(t *testing.T, budget *ByteBudget, slots int) (*tun.UDPNat, N.PacketConn, M.Socksaddr, M.Socksaddr) {
	t.Helper()
	handler := &queueHandler{connections: make(chan N.PacketConn, 1)}
	ctx := context.Background()
	queue := tun.NewUDPNat(tun.UDPNatOptions{Handler: handler, Prepare: func(source, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
		return true, ctx, discardWriter{}, nil
	}, Timeout: time.Second, MaxSize: 64, Mapping: tun.NATMappingAddressAndPortDependent, Filtering: tun.NATFilteringAddressAndPortDependent, PacketQueueSlots: slots, PacketMemoryBudget: budget})
	if err := queue.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	source := M.ParseSocksaddr("198.18.0.1:10000")
	destination := M.ParseSocksaddr("192.0.2.1:53")
	queue.NewPacket([][]byte{make([]byte, 100)}, source, destination, nil)
	select {
	case conn := <-handler.connections:
		t.Cleanup(func() { _ = conn.Close() })
		return queue, conn, source, destination
	case <-time.After(time.Second):
		t.Fatal("queue did not create a real association")
		return nil, nil, source, destination
	}
}

// Per-association packet defaults cannot replace aggregate pre-copy admission.
// A second datagram must be dropped when the shared byte ledger is exhausted.
func TestActualUDPQueueRejectsByteOverflowBeforeCopy(t *testing.T) {
	budget := NewBudget(384)
	queue, conn, source, destination := newQueue(t, budget, 16)
	if budget.Used() == 0 || budget.Used() > 384 {
		t.Fatal("queue allocation did not acquire byte admission")
	}
	queue.NewPacket([][]byte{make([]byte, 100)}, source, destination, nil)
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := buf.NewSize(65507)
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil || buffer.Len() != 100 {
		t.Fatal("first admitted packet was lost")
	}
	buffer.Reset()
	if _, err := conn.ReadPacket(buffer); err == nil {
		t.Fatal("overflow packet was copied into the real queue")
	}
	_ = conn.Close()
	if budget.Used() != 0 {
		t.Fatal("dequeue/close retained packet byte ownership")
	}
}

// Slot admission and byte admission are independent: small packets cannot grow
// a per-flow queue to the upstream 64-entry default.
func TestActualUDPQueueEnforcesSlotsAndDrainsOnClose(t *testing.T) {
	budget := NewBudget(1048576)
	queue, conn, source, destination := newQueue(t, budget, 2)
	for i := 0; i < 3; i++ {
		queue.NewPacket([][]byte{make([]byte, 100)}, source, destination, nil)
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := buf.NewSize(65507)
	defer buffer.Release()
	for i := 0; i < 2; i++ {
		buffer.Reset()
		if _, err := conn.ReadPacket(buffer); err != nil {
			t.Fatal("admitted queue slot was lost")
		}
	}
	buffer.Reset()
	if _, err := conn.ReadPacket(buffer); err == nil {
		t.Fatal("queue ignored configured packet-slot admission")
	}
	queue.NewPacket([][]byte{make([]byte, 100)}, source, destination, nil)
	_ = conn.Close()
	if budget.Used() != 0 {
		t.Fatal("close did not drain owned packet allocations")
	}
}
