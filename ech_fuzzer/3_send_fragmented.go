package ech_fuzzer

import (
	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type SendFragmented struct{}

func (s *SendFragmented) Init(all bool) []*RequestWord {
	//Technically combines servername_padding with fragmenting the packets
	var requestWords []*RequestWord
	var requestWord *RequestWord
	// retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			fragSize := util.GenerateFragSize()
			requestWord = &RequestWord{
				FragSize:   fragSize,
				Servername: "%s",
			}
		}
		requestWords = append(requestWords, requestWord)
	} else {
		allFragSizes := util.GenerateAllFragSizes()
		for _, fragSize := range allFragSizes {
			requestWords = append(requestWords, &RequestWord{FragSize: fragSize})
		}
	}
	return requestWords
}

func (s *SendFragmented) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	if requestWord.FragSize == 0 {
		return MakeConnection(target, hostname, requestWord)
	}
	return MakeConnectionFrag(target, hostname, requestWord)
}
