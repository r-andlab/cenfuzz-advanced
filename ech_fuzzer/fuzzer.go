package ech_fuzzer

import (
	//"log"

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
	flag := true

	//Fetch the ECH Config (byte string)
	echConfig := FetchECHConfig(requestWord.Servername)
	if echConfig == nil {
		//No ECH config -> Just send using Google parrot
		//log.Printf("[ech_fuzzer.BuildECHExtension] Error fetching ECH Config for %s", requestWord.Servername)
		flag = false
	}

	//Create the config
	config := CreateECHConfig(requestWord, echConfig)

	//Apply Custom ClientHello Spec to the config
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS13,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "cloudflare-ech.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h3", "h2", "http/1.1"}},
		},
	}

	conn := connection.NewConnection(target, 443)
	if conn == nil {
		return requestWord, nil, "Dial"
	}

	response := connection.SendECHRequest(conn, *config, *spec, flag)
	if conn.Err != nil {
		return requestWord, nil, conn.Err.Error()
	}
	return requestWord, response, nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
