package ech_fuzzer

import (
	"github.com/censoredplanet/CenFuzz/connection"
	cmp "github.com/google/go-cmp/cmp"
	utls "github.com/refraction-networking/utls"
)

type RequestWord struct {
	Servername   string
	CipherSuites []uint16
	MinVersion   uint16
	MaxVersion   uint16
	Certificate  []utls.Certificate
	ECHConfig    []byte // Needed for storing ECH configuration
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
func CreateECHConfig(requestWord RequestWord) *utls.Config {
	echConfig := utls.ECHConfig{
		Version: utls.VersionTLS13,
		Contents: utls.ECHConfigContents{
			PublicName: []byte(requestWord.Servername),
		},
	}
	config := &utls.Config{
		ServerName:         requestWord.Servername,
		InsecureSkipVerify: true,
		CipherSuites:       requestWord.CipherSuites,
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
		Certificates:       requestWord.Certificate,
		ECHConfigs:         []utls.ECHConfig{echConfig},
	}

	return config

}

func MakeConnection(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	config := CreateECHConfig(requestWord)

	conn := connection.NewConnection(target, 443)
	if conn == nil {
		return requestWord, nil, "Dial"
	}

	response := connection.SendHTTPSRequest(conn, *config)
	if conn.Err != nil {
		return requestWord, nil, conn.Err.Error()
	}
	return requestWord, response, nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
