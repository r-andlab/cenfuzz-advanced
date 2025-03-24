package quic_fuzzer

import (
	//"crypto/x509"
	//"log"
	//"strconv"
	//"strings"
	"fmt"

	"github.com/censoredplanet/CenFuzz/connection"
	//"github.com/censoredplanet/CenFuzz/util"
	"github.com/google/go-cmp/cmp"
	// tld "github.com/jpillora/go-tld"
	//utls "github.com/refraction-networking/utls"
	// this packet is need for quic connections to the server
	//"github.com/quic-go/quic-go"
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
	method := "GET"
	if requestWord.GetWord != "" {
		method = requestWord.GetWord
	}

	// HTTP/3 as the protocol version
	httpVersion := "HTTP/3"
	if requestWord.QUICWord != "" {
		httpVersion = requestWord.QUICWord
	}

	// Default path is "/" if not provided
	path := "/"
	if requestWord.Path != "" {
		path = requestWord.Path
	}

	// Ensure Host header is included
	host := requestWord.Hostname
	if host == "" {
		host = "example.com" // Default host if not specified
	}

	// Assemble the HTTP/3 request
	request := fmt.Sprintf(
		"%s %s %s\r\nHost: %s\r\nUser-Agent: YourUserAgent\r\nConnection: close\r\n\r\n",
		method, path, httpVersion, host)

	return request
}
func MakeConnectionQuic(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	formattedHostname := FormatHttpRequest(requestWord)

	conn := connection.NewQUICConnection(target, 443)
	if conn == nil {
		return formattedHostname, nil, "Dial"
	}

	response := connection.SendHTTP3Request(conn, formattedHostname)
	if conn.Err != nil {
		return formattedHostname, nil, conn.Err.Error()
	}
	return formattedHostname, response, nil
}


type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
