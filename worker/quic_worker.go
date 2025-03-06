package worker

import (
	// "fmt"
	// "log"
	// "sync"
	// "time"

	"quic_fuzzer"
	// "github.com/censoredplanet/CenFuzz/util"
)

type QUICWorker struct{}

func (f FuzzerSpec) QuicFuzzerInterface() quic_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		return &http_fuzzer.HostnamePadding{}
	default:
		panic("unknown fuzzer")
	}
}
