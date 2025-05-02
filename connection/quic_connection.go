package connection

// import (
// 	"bytes"
// 	"crypto/tls"
// 	"crypto/x509"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	//"regexp"
// 	//"strings"

// 	"github.com/quic-go/quic-go"
// 	"github.com/quic-go/quic-go/http3"
// 	"github.com/quic-go/quic-go/qlog"
// )

// // SendHTTPRequest sends an HTTP/3 request over QUIC
// func SendHTTP3Request( request string) interface{} {

// 	fmt.Println("request = ", request)
// 	pool, err := x509.SystemCertPool()
// 	if err != nil {
// 		log.Fatal(err)
// 	}


// 	roundTripper := &http3.Transport{
// 		TLSClientConfig: &tls.Config{
// 			RootCAs:            pool,
// 			InsecureSkipVerify: false,
// 			//KeyLogWriter:       keyLog,
// 		},
// 		QUICConfig: &quic.Config{
// 			Tracer: qlog.DefaultConnectionTracer,
// 		},
// 	}
// 	defer roundTripper.Close()
// 	hclient := &http.Client{
// 		Transport: roundTripper,
// 	}

// 	addr := "https://" + request
// 	log.Printf("GET %s", addr)
// 	rsp, err := hclient.Get(addr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	log.Printf("Got response for %s: %#v", addr, rsp)

// 	body := &bytes.Buffer{}
// 	_, err = io.Copy(body, rsp.Body)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
	

// 	return body
	
// }