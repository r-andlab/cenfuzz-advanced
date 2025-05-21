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

// added helper function
func randomBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}


type HeaderAppendValidation struct{}

func (q *HeaderAppendValidation) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < config.NumberOfProbesPerTest; i++ {
		payload := make([]byte, 100)
		r.Read(payload)
		// Append garbage to header simulation
		payload = append(payload, []byte{0x00, 0x00, 0xBE, 0xEF}...)

		requestWords = append(requestWords, &RequestWord{
			DCID:       randomBytes(r, 8),
			SCID:       randomBytes(r, 8),
			Version:    1,
			PacketType: 0x1,
			Token:      []byte{},
			Length:     1200,
			Payload:    payload,
		})
	}
	return requestWords
}

func (q *HeaderAppendValidation) Fuzz(target, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(requestWord)
	return quic.Fuzz(buf.Bytes(), target)
}