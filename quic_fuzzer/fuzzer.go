package quic_fuzzer

import (
	"fmt"
	"time"

	//"github.com/censoredplanet/CenFuzz/connection"
	"github.com/google/go-cmp/cmp"
	"github.com/quic-go/quic-go/fuzzing/header"

)
type RequestWord struct {
	Hostname          string
	GetWord           string `default:"GET"`
	QUICWord          string `default:"HTTP/3.3"`
	HostWord          string `default:"Host:"`
	QUICDelimiterWord string `default:"\r\n"`
	Path              string `default:"/"`
	Header            string `default:""`
	ALPN              string `default:"h3"`
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}


// FormatHttpRequest builds HTTP/3 pseudo-headers from a RequestWord
func FormatHttpRequest(req RequestWord) string {
	// Customize this as needed — this is a simple example:
	return fmt.Sprintf(":method: GET\r\n:path: %s\r\n:authority: %s\r\nuser-agent: quic-go-client\r\n%s\r\n",
		req.Path, req.Hostname, req.Header)
}

// MakeConnectionQuicNormal establishes a QUIC connection and sends an HTTP/3 request
func MakeConnectionQuicNormal(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	// Step 1: Establish the QUIC connection
	conn := connection.NewQUICConnection(target, 443)
	if conn == nil || conn.Raw == nil {
		return hostname, nil, fmt.Errorf("failed to connect to %s", target)
	}

	// Step 2: Open a new QUIC stream
	stream, err := conn.Raw.OpenStreamSync(context.Background())
	if err != nil {
		return hostname, nil, fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.Close()
	defer conn.Udpport.Close()

	// Step 3: Build HTTP/3 headers from requestWord
	headers := FormatHttpRequest(requestWord)

	// Step 4: Build a HEADERS frame (0x01) with quicvarint
	buf := &bytes.Buffer{}
	buf.Write(quicvarint.Append(nil, 0x01))                        // HEADERS frame type
	buf.Write(quicvarint.Append(nil, uint64(len(headers))))       // length
	buf.Write([]byte(headers))                                    // actual header payload

	// Step 5: Send the HEADERS frame
	if _, err := stream.Write(buf.Bytes()); err != nil {
		return hostname, nil, fmt.Errorf("failed to send headers: %v", err)
	}

	// Step 6: Read the response (assume immediate reply on same stream)
	respBuf := make([]byte, 2048)
	stream.SetReadDeadline(time.Now().Add(2 * time.Second)) // Optional: timeout
	n, err := stream.Read(respBuf)
	if err != nil && err != io.EOF {
		return hostname, nil, fmt.Errorf("failed to read response: %v", err)
	}

	return hostname, respBuf[:n], nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
