package quic_fuzzer

// import (
// 	"fmt"
// 	"time"

// 	//"github.com/censoredplanet/CenFuzz/connection"
// 	"github.com/google/go-cmp/cmp"
// 	"github.com/quic-go/quic-go/fuzzing/header"

// )
// type RequestWord struct {
// 	Hostname          string
// 	GetWord           string `default:"GET"`
// 	QUICWord          string `default:"HTTP/3.3"`
// 	HostWord          string `default:"Host:"`
// 	QUICDelimiterWord string `default:"\r\n"`
// 	Path              string `default:"/"`
// 	Header            string `default:""`
// 	ALPN              string `default:"h3"`
// }

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

// // MakeConnectionQuicNormal establishes a QUIC connection and sends an HTTP/3 request
// func MakeConnectionQuicNormal(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	
// }

// type Fuzzer interface {
// 	Init(all bool) []*RequestWord
// 	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
// }
