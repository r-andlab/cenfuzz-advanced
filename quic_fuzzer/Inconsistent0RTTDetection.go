package quic_fuzzer

import (
	//"fmt"
	//"log"
	"bytes"
	"encoding/gob"
	"math/rand"
	"time"

	"github.com/censoredplanet/CenFuzz/config"
	//"github.com/censoredplanet/CenFuzz/util"
	quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"
)



type Inconsistent0RTTDetection struct{}

func (q *Inconsistent0RTTDetection) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < config.NumberOfProbesPerTest; i++ {
		packetType := byte(0x1)
		if r.Intn(2) == 1 {
			packetType = 0x3 // Set as 0-RTT packet type
		}

		requestWords = append(requestWords, &RequestWord{
			DCID:       randomBytes(r, 8),
			SCID:       randomBytes(r, 8),
			Version:    1,
			PacketType: packetType,
			Token:      []byte{},
			Length:     1200,
			Payload:    []byte{0x17, 0x03}, // TLS record hint
		})
	}
	return requestWords
}

func (q *Inconsistent0RTTDetection) Fuzz(target, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(requestWord)
	return quic.Fuzz(buf.Bytes(), target)
}
