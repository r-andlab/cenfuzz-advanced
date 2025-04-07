package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
	"bytes"
	"github.com/quic-go/quic-go/quicvarint"  // for quicvarint.Write


	quic "github.com/quic-go/quic-go"
	
)

// QUICConnection struct for handling QUIC connections
type QUICConnection struct {
	Host string
	Raw  quic.Connection
	Err  error
	Udpport net.Conn
}

// NewQUICConnection establishes a new QUIC connection and ensures handshake completion
func NewQUICConnection(host string, port uint) *QUICConnection {
	// TO DO: change from returning nil to raising an error 

	// TO DO: stop hard coding of the port
	host = host + ":443"

	// getting the server addr with udp 
	server_addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		fmt.Println("Error resolving domain:", err)
		return nil
	}

	// getting my own address
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
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
	return &QUICConnection{Host: host, Raw: quic_conn, Err: nil, Udpport: conn}

	



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
	

	// Create a buffer to send raw HTTP/3 frames
	buf := &bytes.Buffer{}

	// Send SETTINGS frame first (with 0x04 as the frame type)
	// 0x04 is SETTINGS frame, we'll send it empty for now

	settingsPayload := []byte{ // A minimal valid SETTINGS frame with one setting
		0x01, 0x00, 0x00, 0x00, 0x01, // First setting: Max streams
	}

	buf.Write(quicvarint.Append(nil, uint64(len(settingsPayload))))
	buf.Write(settingsPayload)
	_, err = stream.Write(buf.Bytes())
	if err != nil {
		fmt.Println("Error sending SETTINGS frame:", err)
		return nil
	}

	// // Clear the buffer before sending HEADERS frame
	// buf.Reset()

	// // Send HEADERS frame (0x01 = HEADERS)
	// buf.Write(quicvarint.Append(nil, 0x01)) // 0x01 = HEADERS frame type

	// // Craft the raw HTTP/3 headers (GET /index.html)
	// tempRequest := []byte(":method: GET\r\n" +
	// 	":path: /index.html\r\n" +
	// 	":authority: quic.tech\r\n" +
	// 	"User-Agent: quic-go-client\r\n" +
	// 	"\r\n")

	// // Frame Length: length of the HTTP/3 headers
	// buf.Write(quicvarint.Append(nil, uint64(len(tempRequest))))

	// // Frame Payload: the actual HTTP/3 headers
	// buf.Write(tempRequest)

	// _, err = stream.Write(buf.Bytes())
	// if err != nil {
	// 	fmt.Println("Error sending request:", err)
	// 	return nil
	// }

	// // Read response
	response_buf := make([]byte, 1024)
	n, err := stream.Read(response_buf)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading response:", err)
		return nil
	}

	fmt.Println("Response from server:", string(response_buf[:n]))
	defer stream.Close()

	defer conn.Udpport.Close()
	return response_buf[:n]

	// return nil
}