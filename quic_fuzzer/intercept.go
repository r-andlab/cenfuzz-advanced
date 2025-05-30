package quic_fuzzer

import (
	"net"
	"sync"
)

// CapturedPacket holds the packet bytes and address.
type CapturedPacket struct {
	Direction string // "send" or "recv"
	Bytes     []byte
	Addr      net.Addr
}

// InterceptConn wraps a net.PacketConn and intercepts packets.
type InterceptConn struct {
	net.PacketConn
	mu       sync.Mutex
	Packets  []CapturedPacket // captured packets
	Active   bool              // enable/disable capture
}

// NewInterceptConn wraps a PacketConn for interception
func NewInterceptConn(conn net.PacketConn) *InterceptConn {
	return &InterceptConn{
		PacketConn: conn,
		Active:     true,
		Packets:    make([]CapturedPacket, 0),
	}
}

// WriteTo intercepts outgoing packets
func (i *InterceptConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if i.Active {
		i.mu.Lock()
		i.Packets = append(i.Packets, CapturedPacket{
			Direction: "send",
			Bytes:     append([]byte(nil), b...), // copy buffer
			Addr:      addr,
		})
		i.mu.Unlock()
	}
	return i.PacketConn.WriteTo(b, addr)
}

// ReadFrom intercepts incoming packets
func (i *InterceptConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := i.PacketConn.ReadFrom(b)
	if err == nil && i.Active {
		i.mu.Lock()
		i.Packets = append(i.Packets, CapturedPacket{
			Direction: "recv",
			Bytes:     append([]byte(nil), b[:n]...), // copy only read bytes
			Addr:      addr,
		})
		i.mu.Unlock()
	}
	return n, addr, err
}

// GetCaptured returns and clears captured packets
func (i *InterceptConn) GetCaptured() []CapturedPacket {
	i.mu.Lock()
	defer i.mu.Unlock()
	packets := i.Packets
	i.Packets = nil
	return packets
}
