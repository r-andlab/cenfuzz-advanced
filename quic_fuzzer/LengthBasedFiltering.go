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

type LengthBasedFiltering struct{}

func (q *LengthBasedFiltering) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < config.NumberOfProbesPerTest; i++ {
		length := 100 + r.Intn(1400) // Vary length between 100 and 1500

		requestWords = append(requestWords, &RequestWord{
			DCID:       randomBytes(r, 8),
			SCID:       randomBytes(r, 8),
			Version:    1,
			PacketType: 0x1,
			Token:      []byte{},
			Length:     uint64(length),
			Payload:    make([]byte, length),
		})
	}
	return requestWords
}

func (q *LengthBasedFiltering) Fuzz(target, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(requestWord)
	return quic.Fuzz(buf.Bytes(), target)
}