package ech_fuzzer

import (
	"fmt"
	"log"

	"github.com/censoredplanet/CenFuzz/connection"
	cmp "github.com/google/go-cmp/cmp"
	dns "github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

type RequestWord struct {
	Servername   string
	CipherSuites []uint16
	MinVersion   uint16
	MaxVersion   uint16
	Certificate  []utls.Certificate
	ECHConfig    []byte
	FragSize     int
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}

func FetchECHConfig(domain string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil
	}

	//Parse the answer to check if it's an HTTPS record and return the public key
	for _, ans := range in.Answer {
		if httpsRecord, ok := ans.(*dns.HTTPS); ok {
			for _, kv := range httpsRecord.Value {
				if kv.Key() == 0x0005 {
					if echVal, ok := kv.(*dns.SVCBECHConfig); ok {
						//Return value as a byte string
						return echVal.ECH
					}
				}
			}
		}
	}

	return nil
}

func CreateECHConfig(requestWord RequestWord, echConfigListBytes []byte) *utls.Config {
	config := &utls.Config{
		ServerName:                     requestWord.Servername,
		InsecureSkipVerify:             true,
		CipherSuites:                   requestWord.CipherSuites,
		MinVersion:                     utls.VersionTLS13,
		MaxVersion:                     utls.VersionTLS13,
		Certificates:                   requestWord.Certificate,
		EncryptedClientHelloConfigList: echConfigListBytes,
	}

	return config
}

func MakeConnection(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	//Fetch the ECH Config (byte string)
	echConfig := FetchECHConfig(requestWord.Servername)
	if requestWord.ECHConfig != nil { //requestWord ECHConfig was fuzzed/has padding
		echConfig = []byte(fmt.Sprintf(string(requestWord.ECHConfig), echConfig))
		log.Printf("%x", echConfig)
	}

	//Create the config
	config := CreateECHConfig(requestWord, echConfig)

	//Recreate updated requestword
	request := &RequestWord{
		Servername:   config.ServerName,
		CipherSuites: config.CipherSuites,
		MinVersion:   config.MinVersion,
		MaxVersion:   config.MaxVersion,
		Certificate:  config.Certificates,
		ECHConfig:    config.EncryptedClientHelloConfigList,
		FragSize:     0,
	}

	conn := connection.NewConnection(target, 443)
	if conn == nil {
		return request, nil, "Dial"
	}

	response := connection.SendECHRequest(conn, *config)
	if conn.Err != nil {
		return request, nil, conn.Err.Error()
	}
	return request, response, nil
}

func MakeConnectionFrag(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	//Fetch the ECH Config (byte string)
	echConfig := FetchECHConfig(requestWord.Servername)

	//Create the config
	config := CreateECHConfig(requestWord, echConfig)

	//Recreate updated requestword
	request := &RequestWord{
		Servername:   config.ServerName,
		CipherSuites: config.CipherSuites,
		MinVersion:   config.MinVersion,
		MaxVersion:   config.MaxVersion,
		Certificate:  config.Certificates,
		ECHConfig:    config.EncryptedClientHelloConfigList,
	}

	conn := connection.NewConnection(target, 443)
	if conn == nil {
		return request, nil, "Dial"
	}

	response := connection.SendECHFrag(conn, *config, requestWord.FragSize)
	if conn.Err != nil {
		return request, nil, conn.Err.Error()
	}
	return request, response, nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
