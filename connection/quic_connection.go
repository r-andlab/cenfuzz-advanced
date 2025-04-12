package connection

import (
	//"context"
	"crypto/tls"
	"crypto/x509"
	//"fmt"
	"io"
	//"os"
	"log"
	//"flag"
	"net/http"
	//"time"
	"bytes"
	//"sync"



	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	
)

// NewQUICConnection establishes a new QUIC connection and ensures handshake completion
// func NewQUICConnection(host string, port uint) *QUICConnection {
// 	// TO DO: change from returning nil to raising an error
// 	// TO DO: stop hard coding of the port
// 	host = host + ":443"

// 	// getting the server addr with udp
// 	server_addr, err := net.ResolveUDPAddr("udp", host)
// 	if err != nil {
// 		fmt.Println("Error resolving domain:", err)
// 		return nil
// 	}

// 	// getting my own address
// 	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
// 	if err != nil {
// 		fmt.Println("Problem setting up udp address", err)
// 		return nil
// 	}

// 	// setting up a udp port on my own device
// 	conn, err := net.ListenUDP("udp", addr)
// 	if err != nil {
// 		fmt.Println("Problem setting up udp port", err)
// 		return nil
// 	}

// 	// Open or create the SSL keylog file
// 	keyLogFile, err := os.OpenFile("/home/mike/Documents/sslkeylog/sslkeylogfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		fmt.Println("Error opening SSL keylog file:", err)
// 		return nil
// 	}
// 	defer keyLogFile.Close()

// 	// my tls config with KeyLogWriter for SSL key logging
// 	tlsConfig := &tls.Config{
// 		// Don't skip verification in production; only for testing
// 		InsecureSkipVerify: true,
// 		MinVersion:         tls.VersionTLS13,
// 		NextProtos:         []string{"h3"},
// 		KeyLogWriter:       keyLogFile, // Log the SSL keys to the specified file
// 	}

// 	// Create a QUIC configuration
// 	quicConfig := &quic.Config{
// 		MaxIdleTimeout:   10 * time.Second,
// 		MaxIncomingStreams: 1000,
// 	}

// 	// Establish QUIC connection with timeout
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
// 	defer cancel()
// 	quic_conn, err := quic.Dial(ctx, conn, server_addr, tlsConfig, quicConfig)
// 	if err != nil {
// 		fmt.Println("Error in creating connection", err)
// 		return nil
// 	}

// 	// returning the quic_conn
// 	return &QUICConnection{Host: host, Raw: quic_conn, Err: nil, Udpport: conn}
// }

// SendHTTPRequest sends an HTTP/3 request over QUIC
func SendHTTP3Request( request string) interface{} {


	// var keyLog io.Writer
	// if len(*keyLogFile) > 0 {
	// 	f, err := os.Create(*keyLogFile)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	defer f.Close()
	// 	keyLog = f
	// }

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}


	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
			//KeyLogWriter:       keyLog,
		},
		QUICConfig: &quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	//hard coding for now
	addr := "https://quic.nginx.org"

	log.Printf("GET %s", addr)
	rsp, err := hclient.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got response for %s: %#v", addr, rsp)

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
	

	return body
	
}