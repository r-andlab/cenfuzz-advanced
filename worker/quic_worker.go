package worker

import (
	"fmt"
	// "log"
	// "sync"
	// "time"

	"cenfuzz-advanced/quic_fuzzer"
	// "github.com/censoredplanet/CenFuzz/util"
)

type QUICWorker struct{}

func (f FuzzerSpec) QuicFuzzerInterface() quic_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		// return &quic_fuzzer.HostnamePadding{}
		fmt.Println("we are attempting to do the padding here")
		return &quic_fuzzer.HostnamePadding{}
	default:
		panic("unknown fuzzer")
	}
}
