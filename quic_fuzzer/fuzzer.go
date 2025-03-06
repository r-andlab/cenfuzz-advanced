package quic_fuzzer

import (
	// "crypto/x509"
	// "log"
	// "strconv"
	// "strings"

	// "github.com/censoredplanet/CenFuzz/connection"
	// "github.com/censoredplanet/CenFuzz/util"
	"github.com/google/go-cmp/cmp"
	// tld "github.com/jpillora/go-tld"
	// utls "github.com/refraction-networking/utls"
)

type RequestWord struct {
	Hostname          string
	GetWord           string `default:"GET"`
	HttpWord          string `default:"HTTP/1.1"`
	HostWord          string `default:"Host:"`
	HttpDelimiterWord string `default:"\r\n"`
	Path              string `default:"/"`
	Header            string `default:""`
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}
