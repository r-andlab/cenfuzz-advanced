package quic_fuzzer

import (
	//"fmt"
	"log"

	"github.com/censoredplanet/CenFuzz/connection"
	"github.com/google/go-cmp/cmp"

)
type RequestWord struct {
	Hostname          string
	GetWord           string `default:"GET"`
	QUICWord          string `default:"HTTP/3.3"`
	HostWord          string `default:"Host:"`
	QUICDelimiterWord string `default:"\r\n"`
	Path              string `default:"/"`
	Header            string `default:""`
	ALPN              string `default:"h3"`
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}

// Returns of an HTTP request for URL.
// Returns a properly formatted HTTP/3 request for a URL.
func FormatHttpRequest(requestWord RequestWord) string {
	// Use GET as the default method if none is provided
	// method := "GET"
	// if requestWord.GetWord != "" {
	// 	method = requestWord.GetWord
	// }

	// HTTP/3 as the protocol version
	// httpVersion := "HTTP/3"
	// if requestWord.QUICWord != "" {
	// 	httpVersion = requestWord.QUICWord
	// }

	// Default path is "/" if not provided
	// path := "/"
	// if requestWord.Path != "" {
	// 	path = requestWord.Path
	// }

	// Ensure Host header is included
	// host := requestWord.Hostname
	// if host == "" {
	// 	host = "example.com" // Default host if not specified
	// }

	// Assemble the HTTP/3 request
	// request := fmt.Sprintf(
	// 	"%s %s %s\r\nHost: %s\r\nUser-Agent: YourUserAgent\r\nConnection: close\r\n\r\n",
	// 	method, path, httpVersion, host)

	return requestWord.Hostname
}
func MakeConnectionQuic(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	log.Println("request word is ", requestWord)
	formattedHostname := FormatHttpRequest(requestWord)

	response := connection.SendHTTP3Request(formattedHostname)

	return formattedHostname, response, nil
}


type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
