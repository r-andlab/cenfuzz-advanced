package ech_fuzzer

import (
	"encoding/base64"
	"log"

	goech "github.com/OmarTariq612/goech"
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
	in, _, err := c.Exchange(m, "8.8.8.8:53") // Using Google's public DNS
	if err != nil {
		return nil
	}

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

func BuildECHExtension(b64ECHConfig string) utls.TLSExtension {
	echConfigList, err := goech.ECHConfigListFromBase64(b64ECHConfig)
	if err != nil {
		log.Println("[ech_fuzzer.BuildECHExtension] Error parsing certificate")
		return nil
	}

	pk, _ := echConfigList[0].PublicKey.MarshalBinary()
	if err != nil {
		log.Println("[ech_fuzzer.BuildECHExtension] Error marshalling binary")
	}

	echExt := &utls.GenericExtension{
		Id:   0xfe0d,
		Data: pk,
	}

	return echExt
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
		//No ECH config -> Just send using
		log.Printf("[ech_fuzzer.BuildECHExtension] Error fetching ECH Config for %s", requestWord.Servername)
		flag = false
	}

	//Create ECH Extension (used in case there are multiple configs)
	echExtension := BuildECHExtension(base64.StdEncoding.EncodeToString(echConfig))

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
			echExtension,
			&utls.SNIExtension{ServerName: "bruh.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
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
