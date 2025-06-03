package ech_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type ECHConfigPadding struct{}

func (s *ECHConfigPadding) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			ECHConfigWithRandomPadding := util.GenerateECHConfigRandomPadding()
			requestWord = &RequestWord{
				ECHConfig:  []byte(ECHConfigWithRandomPadding),
				Servername: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[ECHConfigPadding.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		ECHConfigAllPadding := util.GenerateAllECHConfigPaddings()
		for _, echConfig := range ECHConfigAllPadding {
			requestWords = append(requestWords, &RequestWord{ECHConfig: []byte(echConfig), Servername: "%s"})
		}
	}
	return requestWords
}

func (s *ECHConfigPadding) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
