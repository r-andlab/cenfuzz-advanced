package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

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
	// TO DO: change from returning nil to raising an error 

	// TO DO: stop hard coding of the port
	host = host + ":4433"

	// getting the server addr with udp 
	server_addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		fmt.Println("Error resolving domain:", err)
		return nil
	}

	// getting my own address
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:6121")
	if err != nil {
		fmt.Println("Problem setting up udp address", err)
		return nil
	}

	// setting up a udp port on my own device
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Problem setting up udp port", err)
		return nil
	}

	// my tls confid
	tlsConfig := &tls.Config{
		// TO DO: don't skip the verification in production
		InsecureSkipVerify: true,             // For testing purposes; skip verification
		MinVersion:         tls.VersionTLS13, 
		NextProtos:         []string{"h3"},   
	}

	// Create a QUIC configuration
	quicConfig := &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
		MaxIncomingStreams: 1000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
	defer cancel()
	quic_conn, err := quic.Dial(ctx, conn, server_addr, tlsConfig, quicConfig)
	if err != nil {
		fmt.Println("Error in creating connection", err)

		return nil
	}


	// returning the quic_conn
	return &QUICConnection{Host: host, Raw: quic_conn, Err: nil}

	



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
	temp_request := "GET /index.html HTTP/3.0\r\n" +
		":method: GET\r\n" +
		":path: /index.html\r\n" +
		":authority: quic.tech\r\n" +
		"User-Agent: quic-go-client\r\n" +
		"\r\n"

	_, err = stream.Write([]byte(temp_request))
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading response:", err)
		return nil
	}

	fmt.Println("Response from server:", string(buf[:n]))

	return buf[:n]
}