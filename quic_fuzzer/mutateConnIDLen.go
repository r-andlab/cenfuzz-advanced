package quic_fuzzer

import (
	"fmt"
	"log"
	"bytes"
	"encoding/gob"

	"github.com/censoredplanet/CenFuzz/config"
	//"github.com/censoredplanet/CenFuzz/util"
	quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"
)

type MutateConnIDLen struct{}

func (q *MutateConnIDLen) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			fmt.Println("Doing stuff yay!")
			fmt.Println("the request word right now is ", requestWord)
		}
	} else {
		fmt.Println("doing the other stuff not yay!")
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
