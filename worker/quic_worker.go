package worker

import (
	"fmt"
	"log"
	"sync"
	"time"

	"cenfuzz-advanced/quic_fuzzer"
	"github.com/censoredplanet/CenFuzz/util"
)

type QUICWorker struct{}

func (f FuzzerSpec) QUICFuzzerInterface() quic_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		return &quic_fuzzer.HostnamePadding{}
	default:
		panic("unknown fuzzer")
	}
}

func QUICFuzzerMapping(fuzzer int) string {
	switch fuzzer {
	case 1:
		return "Hostname Padding"
	default:
		return "NA"
	}
}


type QUICFuzzerObject struct {
	TestName     string
	Spec         FuzzerSpec
	RequestWords []*quic_fuzzer.RequestWord
}

//Using a separate struct to assign work instead of just the input,
//since in the future we may want to assign different work for each vantage point
type QUICWork struct {
	IP      string
	Domain  string
	Fuzzers []*QUICFuzzerObject
}

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

func (h *QUICWorker) FuzzerObjects(fuzzerList []*util.FuzzerInput) interface{} {
	var fuzzerObjects []*QUICFuzzerObject
	for _, fuzzerStruct := range fuzzerList {

		fuzzerspec := FuzzerSpec(fuzzerStruct.FuzzerNumber)
		fuzzerName := QUICFuzzerMapping(fuzzerStruct.FuzzerNumber)
		if fuzzerName == "NA" {
			log.Println("[QUICWorker.FuzzerObjects] WARNING: Fuzzer not available: ", fuzzerStruct.FuzzerNumber)
			continue
		}
		requestWords := fuzzerspec.QUICFuzzerInterface().Init(fuzzerStruct.All)

		fuzzerObjects = append(fuzzerObjects, &QUICFuzzerObject{
			TestName:     fuzzerName,
			Spec:         fuzzerspec,
			RequestWords: requestWords,
		})
	}
	return fuzzerObjects

}

func (h *QUICWorker) GenerateTemplate(response interface{}, keyword string) interface{} {
	if response == nil {
		return nil
	}
	filterDomain := newDomainFilter(keyword)
	filterBody := func(body string) string {
		body = timestampRegex.ReplaceAllString(body, TimestampReplacmentMarker)
		body = akamaiRegex.ReplaceAllString(body, AkamiIdReplacementMarker)
		return filterDomain(body)
	}

	return filterBody(response.(string))
}

func (h *QUICWorker) MatchesControl(results []*util.Result) []*util.Result {
	var normalResponse interface{}
	var normalError interface{}

	for _, result := range results {
		if result.IsNormal == true {
			normalResponse = h.GenerateTemplate(result.Response, result.Domain)
			normalError = result.Error
		}
	}
	for _, result := range results {
		normalDifferences := ""
		uncensoredDifferences := ""
		resultResponseTemplate := h.GenerateTemplate(result.Response, result.Domain)
		uncensoredResponseTemplate := h.GenerateTemplate(result.UncensoredResponse, result.Domain)
		if resultResponseTemplate == normalResponse && result.Error == normalError {
			result.MatchesNormal = true
		} else {
			if resultResponseTemplate == nil && normalResponse != nil {
				normalDifferences += "No expected response;"
			}
			if result.Error == nil && normalError != nil {
				normalDifferences += "No expected error;"
			}
			if normalResponse != nil && (resultResponseTemplate != normalResponse) {
				normalDifferences += "Different response;"
			}
			if normalError != nil && (result.Error != normalError) {
				normalDifferences += "Different error;"
			}
			result.MatchesNormal = false
			result.NormalDifferences = normalDifferences
		}

		if resultResponseTemplate == uncensoredResponseTemplate && result.Error == result.UncensoredError {
			result.MatchesUncensored = true
		} else {
			if resultResponseTemplate == nil && uncensoredResponseTemplate != nil {
				uncensoredDifferences += "No expected response;"
			}
			if result.Error == nil && result.UncensoredError != nil {
				uncensoredDifferences += "No expected error;"
			}
			if uncensoredResponseTemplate != nil && (resultResponseTemplate != uncensoredResponseTemplate) {
				uncensoredDifferences += "Different response;"
			}
			if result.UncensoredError != nil && (result.Error != result.UncensoredError) {
				uncensoredDifferences += "Different error;"
			}
			result.MatchesUncensored = false
			result.UncensoredDifferences = uncensoredDifferences
		}

	}
	return results
}

func (h *QUICWorker) SendResults(results []*util.Result, ResultsQueue chan<- *util.Result) {
	annotatedResults := h.MatchesControl(results)
	for _, result := range annotatedResults {
		ResultsQueue <- result
	}

}


func (h *QUICWorker) Work(ip string, domain string, fuzzers interface{}) interface{} {
	return &QUICWork{
		IP:      ip,
		Domain:  domain,
		Fuzzers: fuzzers.([]*QUICFuzzerObject),
	}
}


func (h *QUICWorker) Worker(workQueue <-chan interface{}, resultQueue chan<- *util.Result, uncensoredDomain string, wg *sync.WaitGroup, done chan<- bool) {
	for w := range workQueue {
		work := w.(*QUICWork)
		var results []*util.Result

		//Uncensored Normal
		startTime := time.Now()
		uncensoredRequest, uncensoredResponse, uncensoredError := quic_fuzzer.MakeConnectionQuic(work.IP, uncensoredDomain, quic_fuzzer.RequestWord{Hostname: uncensoredDomain})
		time.Sleep(util.Sleep(uncensoredError))
		//Censored Normal
		censoredRequest, censoredResponse, censoredError := quic_fuzzer.MakeConnectionQuic(work.IP, work.Domain, quic_fuzzer.RequestWord{Hostname: work.Domain})
		time.Sleep(util.Sleep(censoredError))
		//We're including the sleep time in endtime because that's the whole time taken for this one measurement. Could do it the other way also.
		endTime := time.Now()
		//Add normal results
		results = append(results, &util.Result{
			IP:                 work.IP,
			Domain:             work.Domain,
			TestName:           "Normal",
			IsNormal:           true,
			Request:            censoredRequest,
			Response:           censoredResponse,
			Error:              censoredError,
			UncensoredRequest:  uncensoredRequest,
			UncensoredResponse: uncensoredResponse,
			UncensoredError:    uncensoredError,
			StartTime:          startTime,
			EndTime:            endTime,
		})

		if Break(censoredError) && Break(uncensoredError) {
			h.SendResults(results, resultQueue)
			wg.Done()
			continue
		}
		var breakFlag bool
		for _, fuzzerObject := range work.Fuzzers {
			breakFlag = false
			for _, requestWord := range fuzzerObject.RequestWords {
				//Uncensored Test
				//Create copy
				uncensoredRequestWord := requestWord.Hostname
				censoredRequestWord := requestWord.Hostname
				formattedUncensoredDomain := fmt.Sprintf(uncensoredRequestWord, uncensoredDomain)
				startTime = time.Now()
				uncensoredRequest, uncensoredResponse, uncensoredErr := fuzzerObject.Spec.QuicFuzzerInterface().Fuzz(work.IP, work.Domain, quic_fuzzer.RequestWord{
					Hostname:          formattedUncensoredDomain,
					GetWord:           requestWord.GetWord,
					QUICWord:          requestWord.QUICWord,
					HostWord:          requestWord.HostWord,
					QUICDelimiterWord: requestWord.QUICDelimiterWord,
					Path:              requestWord.Path,
					Header:            requestWord.Header,
				})
				time.Sleep(util.Sleep(uncensoredErr))
				formattedCensoredDomain := fmt.Sprintf(censoredRequestWord, work.Domain)
				censoredRequest, censoredResponse, censoredErr := fuzzerObject.Spec.QuicFuzzerInterface().Fuzz(work.IP, work.Domain, quic_fuzzer.RequestWord{
					Hostname:          formattedCensoredDomain,
					GetWord:           requestWord.GetWord,
					QUICWord:          requestWord.QUICWord,
					HostWord:          requestWord.HostWord,
					QUICDelimiterWord: requestWord.QUICDelimiterWord,
					Path:              requestWord.Path,
					Header:            requestWord.Header,
				})
				time.Sleep(util.Sleep(censoredErr))
				endTime = time.Now()
				results = append(results, &util.Result{
					IP:                 work.IP,
					Domain:             work.Domain,
					TestName:           fuzzerObject.TestName,
					IsNormal:           false,
					Request:            censoredRequest,
					Response:           censoredResponse,
					Error:              censoredErr,
					UncensoredRequest:  uncensoredRequest,
					UncensoredResponse: uncensoredResponse,
					UncensoredError:    uncensoredErr,
					StartTime:          startTime,
					EndTime:            endTime,
				})
				if Break(censoredError) && Break(uncensoredError) {
					breakFlag = true
					break
				}
			}
			if breakFlag {
				break
			}
		}
		h.SendResults(results, resultQueue)
		wg.Done()
	}
	done <- true

}