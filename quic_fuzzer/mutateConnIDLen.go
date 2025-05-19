package quic_fuzzer

import (
	//"fmt"
	"log"
	"bytes"
	"encoding/gob"
	"math/rand"
	"time"

	"github.com/censoredplanet/CenFuzz/config"
	//"github.com/censoredplanet/CenFuzz/util"
	quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"
)

type MutateConnIDLen struct{}

var Rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func (q *MutateConnIDLen) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord

	// Use local RNG, seeded by time
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			connIDLen := r.Intn(21) // Random length between 0 and 20

			dcid := make([]byte, connIDLen)
			scid := make([]byte, connIDLen)

			_, err1 := r.Read(dcid)
			_, err2 := r.Read(scid)
			if err1 != nil || err2 != nil {
				log.Printf("Failed to generate connection IDs: %v %v", err1, err2)
				continue
			}

			requestWord := &RequestWord{
				DCID:       dcid,
				SCID:       scid,
				Version:    1,     // use draft-29 or placeholder
				PacketType: 0x1,   // Initial packet
				Token:      []byte{},
				Length:     1200,  // typical initial UDP payload
				Payload:    []byte{},
			}

			requestWords = append(requestWords, requestWord)

			//fmt.Printf("Generated RequestWord %d: DCID len=%d, SCID len=%d\n", i, len(dcid), len(scid))
		}
	} else {
		for connIDLen := 0; connIDLen <= 20; connIDLen++ {
			dcid := make([]byte, connIDLen)
			scid := make([]byte, connIDLen)

			r.Read(dcid)
			r.Read(scid)

			requestWord := &RequestWord{
				DCID:       dcid,
				SCID:       scid,
				Version:    1,
				PacketType: 0x1,
				Token:      []byte{},
				Length:     1200,
				Payload:    []byte{},
			}

			requestWords = append(requestWords, requestWord)

			//fmt.Printf("Generated (exhaustive) RequestWord: DCID len=%d, SCID len=%d\n", len(dcid), len(scid))
		}
	}

	return requestWords
}

func (q *MutateConnIDLen) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(requestWord)
	if err != nil {
		log.Fatal(err)
	}
	data := buf.Bytes()
	return quic.Fuzz(data, target)
}
