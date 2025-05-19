package quic_fuzzer

import (
	//"fmt"
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
