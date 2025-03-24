package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	//"io"
	"log"
	//"time"

	quic "github.com/quic-go/quic-go"
)

// QUICConnection struct for handling QUIC connections
type QUICConnection struct {
	Host string
	Raw  quic.Connection
	Err  error
}

// NewQUICConnection establishes a new QUIC connection and ensures handshake completion
func NewQUICConnection(host string, port uint) *QUICConnection {
	conn := &QUICConnection{
		Host: fmt.Sprintf("%s:%d", host, port),
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	quicConfig := &quic.Config{}

	// Use context for QUIC connection
	ctx := context.Background()
	session, err := quic.DialAddr(ctx, conn.Host, tlsConfig, quicConfig)
	if err != nil {
		conn.Err = err
		log.Println("Error dialing QUIC:", err)
		return nil
	}

	// Ensure the handshake completes
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		conn.Err = err
		log.Println("Error completing QUIC handshake:", err)
		return nil
	}
	stream.Close()

	log.Println("QUIC handshake successful with", conn.Host)

	conn.Raw = session
	return conn
}

// SendHTTPRequest sends an HTTP/3 request over QUIC
func SendHTTP3Request(conn *QUICConnection, request string) interface{} {
	defer conn.Raw.CloseWithError(0, "Closing connection")

	stream, err := conn.Raw.OpenStreamSync(context.Background())
	if err != nil {
		log.Println("Error opening QUIC stream:", err)
		conn.Err = err
		return nil
	}
	defer stream.Close()

	// Send request
	_, err = stream.Write([]byte(request))
	if err != nil {
		log.Println("Error writing to QUIC stream:", err)
		conn.Err = err
		return nil
	}

	// Read response
	response := make([]byte, 1<<16)
	n, err := stream.Read(response)
	// if err != nil && err != io.EOF {
	// 	log.Println("Error reading QUIC response:", err)
	// 	conn.Err = err
	// 	return nil
	// }

	return string(response[:n])
}