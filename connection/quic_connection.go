package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/lucas-clemente/quic-go"
)

// Connection struct now supports QUIC
type Connection struct {
	Host string
	Raw  quic.Connection
	Err  error
}

// Establish a new QUIC connection
func NewConnection(host string, port uint) *Connection {
	conn := &Connection{
		Host: host,
	}

	raw, err := Dial(host, port)
	if err != nil {
		conn.handleError(err)
		return nil
	}
	conn.Raw = raw

	return conn
}

// Dial a QUIC connection instead of TCP
func Dial(host string, port uint) (quic.Connection, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // Disable verification for testing purposes
		NextProtos:         []string{"h3"}, // HTTP/3 ALPN
	}

	quicConf := &quic.Config{}

	session, err := quic.DialAddr(fmt.Sprintf("%s:%d", host, port), tlsConf, quicConf)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// Send an HTTP/3 request over QUIC
func SendHTTPRequest(conn *Connection, request string) interface{} {
	defer conn.Raw.CloseWithError(0, "Closing QUIC connection")

	// Open a new QUIC stream
	stream, err := conn.Raw.OpenStreamSync(context.Background())
	if err != nil {
		conn.handleError(err)
		return nil
	}
	defer stream.Close()

	// Send HTTP/3 request
	sent := []byte(request)
	if _, err := stream.Write(sent); err != nil {
		conn.handleError(err)
		return nil
	}

	// Read response from QUIC stream
	maxResponseLength := 1 << 16
	response := make([]byte, maxResponseLength)

	responseLength := 0
	for {
		stream.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := stream.Read(response[responseLength:maxResponseLength])
		if err == io.EOF {
			break
		} else if err != nil {
			conn.handleError(err)
			break
		}
		responseLength += n
	}

	return string(response[:responseLength])
}

// Handle connection errors
func (conn *Connection) handleError(err error) error {
	if err != nil {
		conn.Err = err
		if conn.Raw != nil {
			conn.Raw.CloseWithError(0, "Error occurred")
		}
	}
	return err
}