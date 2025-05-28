package worker

import (
	//"bytes"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"cenfuzz-advanced/quic_fuzzer"

	"github.com/censoredplanet/CenFuzz/util"
	quic "github.com/r-andlab/quic-go/fuzzing/cenfuzz"

)

type QUICWorker struct{}

type QUICFuzzerObject struct {
	TestName     string
	Spec         FuzzerSpec
	RequestWords []*quic_fuzzer.RequestWord
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
		return &quic_fuzzer.MutateConnIDLen{}
	case 2:
		return &quic_fuzzer.DCIDMismatchCheck{}
	case 3:
		return &quic_fuzzer.Inconsistent0RTTDetection{}
	case 4:
		return &quic_fuzzer.RetryPacketPath{}
	case 5:
		return &quic_fuzzer.HeaderAppendValidation{}
	case 6:
		return &quic_fuzzer.LengthBasedFiltering{}
	default:
		panic("unknown fuzzer")
	}
}


func (q *QUICWorker) GenerateTemplate(response interface{}, keyword string) interface{} {
	if response == nil {
		return nil
	}
	// temp func for debugging
	filterBody := func(body interface{}) string {
		return string(body.([]byte))
	}
	fmt.Println("Generate Template internal response is ", filterBody(response))
	return filterBody(response)
}

//TODO: there are more efficient ways of doing this than going through the list twice, but this will do for now
func (q *QUICWorker) MatchesControl(results []*util.Result) []*util.Result {

	return results
}

// the send result func is definitely nessary 
func (q *QUICWorker) SendResults(results []*util.Result	, ResultsQueue chan<- *util.Result) {
	annotatedResults := q.MatchesControl(results)
	for _, result := range annotatedResults {
		ResultsQueue <- result
	}

}

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
		fmt.Println("fuzzer name = ", fuzzerName)
		// creating the requests 
		requestWords := fuzzerspec.QUICFuzzerInterface().Init(fuzzerStruct.All)

		fuzzerObjects = append(fuzzerObjects, &QUICFuzzerObject{
			TestName:     fuzzerName,
			Spec:         fuzzerspec,
			RequestWords: requestWords,
		})

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

		// func to generate normal packet
		normal_packet, err := quic.GenerateValidQUICInitialPacket()
		if err != nil {
			fmt.Println("failed to generate normal QUIC packet:", err)
			return
		}


		startTime := time.Now()
		//uncensoredResponse, uncensoredError := quic.SendInitialQUICPacket("google.com")
		uncensoredResponse, uncensoredError := quic.SendToServer(normal_packet ,"google.com")
		time.Sleep(util.Sleep(uncensoredError))
		//censoredResponse, censoredError := quic.SendInitialQUICPacket("quic.nginx.org")
		censoredResponse, censoredError := quic.SendToServer(normal_packet ,"quic.nginx.org")
		time.Sleep(util.Sleep(censoredError))
		endTime := time.Now()
		fmt.Println("non fuzzed uncensoredResponse", uncensoredResponse)
		fmt.Println("non fuzzed censoredResponse", censoredResponse)

		results = append(results, &util.Result{
			IP:                 work.IP,
			Domain:             work.Domain,
			TestName:           "Normal",
			IsNormal:           true,
			Response:           []byte(censoredResponse),
			Error:              censoredError,
			UncensoredResponse: []byte(uncensoredResponse),
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
				

				startTime = time.Now()
				uncensoredResponse, uncensoredErr := quic.SendToServer(data ,"google.com")
				time.Sleep(util.Sleep(uncensoredErr))
				censoredResponse, censoredErr := quic.SendToServer(data ,requestWord) 
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
					Response:           []byte(censoredResponse),
					Error:              censoredErr,
					//UncensoredRequest:  uncensoredRequest,
					UncensoredResponse: []byte(uncensoredResponse),
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
	fmt.Println("QUICWorker exiting and sending done signal")
	done <- true
}
