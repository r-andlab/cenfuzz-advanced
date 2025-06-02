package quic_fuzzer

import (
	//"fmt"
	"log"
	//"bytes"
	//"encoding/gob"
	"context"
	"math/rand"
	"time"
	"net"
	"crypto/tls"

	//"github.com/censoredplanet/CenFuzz/config"
	//"github.com/censoredplanet/CenFuzz/util"
	// quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"

	quic "github.com/quic-go/quic-go"
)

type MutateConnIDLen struct{}

var Rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func (q *MutateConnIDLen) Init(all bool) []*RequestWord {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Step 1: Set up intercepted UDP conn
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	intercept := NewInterceptConn(udpConn)

	// Step 2: Start QUIC dial in background
	go func() {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
			NextProtos:         []string{"h3"},
		}
		quicConf := &quic.Config{
			HandshakeIdleTimeout: 2 * time.Second,
		}
		addr := &net.UDPAddr{IP: net.ParseIP(serverIP), Port: 443}
		_, _ = quic.Dial(context.Background(), intercept, addr, tlsConf, quicConf)
	}()

	// Step 3: Wait briefly for packets to flow
	time.Sleep(2 * time.Second)
	captured := intercept.GetCaptured()

	// Step 4: Locate the Initial packet
	var initial []byte
	for _, pkt := range captured {
		if pkt.Direction == "send" && len(pkt.Bytes) > 5 && pkt.Bytes[0]&0x80 == 0x80 {
			initial = pkt.Bytes
			break
		}
	}
	if initial == nil {
		return nil, log.Output(1, "No Initial packet captured")
	}

	// Step 5: Mutate DCID/SCID lengths
	dcidLen := rng.Intn(21)
	scidLen := rng.Intn(21)
	dcid := make([]byte, dcidLen)
	scid := make([]byte, scidLen)
	rng.Read(dcid)
	rng.Read(scid)

	mutated := make([]byte, len(initial))
	copy(mutated, initial)

	// Overwrite DCID/SCID fields in-place
	offset := 5
	if offset+1 > len(mutated) {
		return nil, log.Output(1, "Packet too short for DCID length field")
	}
	mutated[offset] = byte(dcidLen)
	offset++
	copy(mutated[offset:], dcid)
	offset += dcidLen
	if offset+1 > len(mutated) {
		return nil, log.Output(1, "Packet too short for SCID length field")
	}
	mutated[offset] = byte(scidLen)
	offset++
	copy(mutated[offset:], scid)

	return mutated, nil
}


func (q *MutateConnIDLen) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	return q.Init(target, hostname)
}
