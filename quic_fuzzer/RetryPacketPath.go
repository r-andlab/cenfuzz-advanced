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

type RetryPacketPath struct{}

func (q *RetryPacketPath) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < config.NumberOfProbesPerTest; i++ {
		token := make([]byte, r.Intn(100)+10)
		r.Read(token)

		requestWords = append(requestWords, &RequestWord{
			DCID:       randomBytes(r, 8),
			SCID:       randomBytes(r, 8),
			Version:    1,
			PacketType: 0x3, // Retry packet
			Token:      token,
			Length:     1200,
			Payload:    []byte{},
		})
	}
	return requestWords
}

func (q *RetryPacketPath) Fuzz(target, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(requestWord)
	return quic.Fuzz(buf.Bytes(), target)
}