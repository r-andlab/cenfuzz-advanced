package quic_fuzzer

import (
	"fmt"
	"bytes"
	"encoding/binary"
	//"time"

	//"github.com/censoredplanet/CenFuzz/connection"
	//"github.com/google/go-cmp/cmp"
)

type RequestWord struct {
	DCID      []byte
	SCID      []byte
	Version   uint32
	PacketType byte
	Token     []byte
	Length    uint64
	Payload   []byte // optional
}

// func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
// 	for _, a := range s {
// 		if cmp.Equal(a, e) {
// 			return true
// 		}
// 	}
// 	return false
// }


// // FormatHttpRequest builds HTTP/3 pseudo-headers from a RequestWord
// func FormatHttpRequest(req RequestWord) string {
// 	// Customize this as needed — this is a simple example:
// 	return fmt.Sprintf(":method: GET\r\n:path: %s\r\n:authority: %s\r\nuser-agent: quic-go-client\r\n%s\r\n",
// 		req.Path, req.Hostname, req.Header)
// }


// type Fuzzer interface {
// 	Init(all bool) []*RequestWord
// 	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
// }

// need the interface for fuzz
type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{})
}


// this is one of my fucntion and what it does is convert my struct into the raw bytes so that they can be send 
func (r RequestWord) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Version (4 bytes)
	if err := binary.Write(buf, binary.BigEndian, r.Version); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}

	// Packet Type (1 byte)
	if err := buf.WriteByte(r.PacketType); err != nil {
		return nil, fmt.Errorf("packet type: %w", err)
	}

	// DCID Length (1 byte) + DCID
	if err := buf.WriteByte(byte(len(r.DCID))); err != nil {
		return nil, fmt.Errorf("dcid len: %w", err)
	}
	if _, err := buf.Write(r.DCID); err != nil {
		return nil, fmt.Errorf("dcid: %w", err)
	}

	// SCID Length (1 byte) + SCID
	if err := buf.WriteByte(byte(len(r.SCID))); err != nil {
		return nil, fmt.Errorf("scid len: %w", err)
	}
	if _, err := buf.Write(r.SCID); err != nil {
		return nil, fmt.Errorf("scid: %w", err)
	}

	// Token Length (varint-style: 2 bytes) + Token
	if err := binary.Write(buf, binary.BigEndian, uint16(len(r.Token))); err != nil {
		return nil, fmt.Errorf("token len: %w", err)
	}
	if _, err := buf.Write(r.Token); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	// Length (8 bytes)
	if err := binary.Write(buf, binary.BigEndian, r.Length); err != nil {
		return nil, fmt.Errorf("length: %w", err)
	}

	// Optional Payload
	if r.Payload != nil {
		if _, err := buf.Write(r.Payload); err != nil {
			return nil, fmt.Errorf("payload: %w", err)
		}
	}

	return buf.Bytes(), nil
}