package worker

import (
	"log"
	"fmt"
	"sync"
	"time"
	"math/rand"

	"github.com/censoredplanet/CenFuzz/util"
	"cenfuzz-advanced/quic_fuzzer"
	quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"
)

type QUICWorker struct{}

type QUICFuzzerObject struct {
	TestName     string
	Spec         FuzzerSpec
}

type QUICWork struct {
	IP      string
	Domain  string
	Fuzzers []*QUICFuzzerObject
}

// this is the fuzzer mapping for quic 
func QUICFuzzerMapping(fuzzer int) string {
	switch fuzzer {
	case 1:
		return "Connection ID Length Mutation"
	case 2:
		return "DCID Mismatch Check"
	case 3:
		return "Inconsistent 0-RTT Detection"
	case 4:
		return "Retry packet path"
	case 5:
		return "Header append validation"
	case 6:
		return "Length-based filtering before network send"
	default:
		return "NA"
	}
}

func (f FuzzerSpec) QUICFuzzerInterface() quic_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		return &quic_fuzzer.mutateConnIDLen{}
	case 2:
		return &quic_fuzzer.mutateConnIDLen{}
	case 3:
		return &quic_fuzzer.mutateConnIDLen{}
	case 4:
		return &quic_fuzzer.mutateConnIDLen{}
	case 5:
		return &quic_fuzzer.mutateConnIDLen{}
	case 6:
		return &quic_fuzzer.mutateConnIDLen{}
	default:
		panic("unknown fuzzer")
	}
}


func (q *QUICWorker) GenerateTemplate(response interface{}, keyword string) interface{} {
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

//TODO: there are more efficient ways of doing this than going through the list twice, but this will do for now
func (q *QUICWorker) MatchesControl(results []*util.Result) []*util.Result {
	var normalResponse interface{}
	var normalError interface{}

	for _, result := range results {
		if result.IsNormal == true {
			normalResponse = q.GenerateTemplate(result.Response, result.Domain)
			normalError = result.Error
		}
	}
	for _, result := range results {
		normalDifferences := ""
		uncensoredDifferences := ""
		resultResponseTemplate := q.GenerateTemplate(result.Response, result.Domain)
		uncensoredResponseTemplate := q.GenerateTemplate(result.UncensoredResponse, result.Domain)
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

// the send result func is definitely nessary 
func (q *QUICWorker) SendResults(results []*util.Result, ResultsQueue chan<- *util.Result) {
	annotatedResults := q.MatchesControl(results)
	for _, result := range annotatedResults {
		ResultsQueue <- result
	}

}

// func (f FuzzerSpec) QUICFuzzerInterface() quic_fuzzer.Fuzzer {
// 	switch f.Fuzzer() {
// 	// Replace with actual QUIC fuzzers
// 	case 1:
// 		return &quic_fuzzer.InitialPacketMutation{}
// 	case 2:
// 		return &quic_fuzzer.QuicVersionSwap{}
// 	default:
// 		panic("unknown QUIC fuzzer")
// 	}
// }

// func QUICFuzzerMapping(fuzzer int) string {
// 	switch fuzzer {
// 	case 1:
// 		return "Initial Packet Mutation"
// 	case 2:
// 		return "QUIC Version Swap"
// 	default:
// 		return "NA"
// 	}
// }

func (q *QUICWorker) Work(ip string, domain string, fuzzers interface{}) interface{} {
	return &QUICWork{
		IP:      ip,
		Domain:  domain,
		Fuzzers: fuzzers.([]*QUICFuzzerObject),
	}
}

func (q *QUICWorker) FuzzerObjects(fuzzerList []*util.FuzzerInput) interface{} {
	var fuzzerObjects []*QUICFuzzerObject
	for _, fuzzerStruct := range fuzzerList {
		// fmt.Println("fuzzerStruct",fuzzerStruct)
		fuzzerspec := FuzzerSpec(fuzzerStruct.FuzzerNumber)
		fuzzerName := QUICFuzzerMapping(fuzzerStruct.FuzzerNumber)
		fmt.Println("fuzzerspec", fuzzerspec)
		if fuzzerName == "NA" {
			log.Println("[HTTPWorker.FuzzerObjects] WARNING: Fuzzer not available: ", fuzzerStruct.FuzzerNumber)
			continue
		}
		//fmt.Println("fuzzer name = ", fuzzerName)

	}
	return fuzzerObjects
}

// func (q *QUICWorker) SendResults(results []*util.Result, ResultsQueue chan<- *util.Result) {
// 	for _, result := range results {
// 		ResultsQueue <- result
// 	}
// }

func (q *QUICWorker) Worker(workQueue <-chan interface{}, resultQueue chan<- *util.Result, uncensoredDomain string, wg *sync.WaitGroup, done chan<- bool) {
	for w := range workQueue {
		work := w.(*QUICWork)
		var results []*util.Result
		fmt.Println("the work is :", work)

		startTime := time.Now()
		uncensoredResponse, uncensoredError := quic.SendInitialQUICPacket("google.com")
		time.Sleep(util.Sleep(uncensoredError))
		censoredResponse, censoredError := quic.SendInitialQUICPacket("quic.nginx.org")
		time.Sleep(util.Sleep(censoredError))
		endTime := time.Now()
		fmt.Println("non fuzzed uncensoredResponse", uncensoredResponse)
		fmt.Println("non fuzzed censoredResponse", censoredResponse)

		results = append(results, &util.Result{
			IP:                 work.IP,
			Domain:             work.Domain,
			TestName:           "Normal",
			IsNormal:           true,
			Response:           censoredResponse,
			Error:              censoredError,
			UncensoredResponse: uncensoredResponse,
			UncensoredError:    uncensoredError,
			StartTime:          startTime,
			EndTime:            endTime,
		})

		if Break(censoredError) && Break(uncensoredError) {
			q.SendResults(results, resultQueue)
			wg.Done()
			continue
		}

		for _, fuzzerObject := range work.Fuzzers {
			//for _, requestWord := range fuzzerObject.RequestWords {
			// dummy loop 
			for _, requestWord := range []string{"quic.nginx.org"} {
				// getting a random time seed for now later on will be able to set the fuzzing strategy 
				rand.Seed(time.Now().UnixNano()) // seed RNG with current time

				// Generate 32 random bytes (change size as needed)
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(rand.Intn(256)) // random byte: 0–255
				}

				startTime = time.Now()
				uncensoredResponse, uncensoredErr := quic.Fuzz(data ,"google.com")
				time.Sleep(util.Sleep(uncensoredErr))
				censoredResponse, censoredErr := quic.Fuzz(data ,requestWord) 
				time.Sleep(util.Sleep(censoredErr))
				endTime = time.Now()

				fmt.Println("uncensoredResponse fuzzed = ", uncensoredResponse)
				fmt.Println("censoredResponse fuzzed = ", censoredResponse)

				results = append(results, &util.Result{
					IP:                 work.IP,
					Domain:             work.Domain,
					TestName:           fuzzerObject.TestName,
					IsNormal:           false,
					//Request:            censoredRequest,
					Response:           censoredResponse,
					Error:              censoredErr,
					//UncensoredRequest:  uncensoredRequest,
					UncensoredResponse: uncensoredResponse,
					UncensoredError:    uncensoredErr,
					StartTime:          startTime,
					EndTime:            endTime,
				})
				if Break(censoredErr) && Break(uncensoredErr) {
					break
				}
			}
		}
		q.SendResults(results, resultQueue)
		wg.Done()
	}
	done <- true
}
