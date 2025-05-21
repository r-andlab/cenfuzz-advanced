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

type DCIDMismatchCheck struct{}

func (q *DCIDMismatchCheck) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < config.NumberOfProbesPerTest; i++ {
		dcid := make([]byte, r.Intn(20)+1)
		scid := make([]byte, len(dcid))
		r.Read(scid)
		copy(dcid, scid)
		dcid[0] ^= 0xFF // force mismatch

		requestWords = append(requestWords, &RequestWord{
			DCID:       dcid,
			SCID:       scid,
			Version:    1,
			PacketType: 0x1,
			Token:      []byte{},
			Length:     1200,
			Payload:    []byte{},
		})
	}
	return requestWords
}

func (q *DCIDMismatchCheck) Fuzz(target, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(requestWord)
	return quic.Fuzz(buf.Bytes(), target)
}