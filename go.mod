module github.com/censoredplanet/CenFuzz

go 1.23.6

require (
	cenfuzz-advanced/quic_fuzzer v0.0.0
	cloud.google.com/go/bigquery v1.42.0
	github.com/banviktor/asnlookup v0.1.0
	github.com/google/go-cmp v0.7.0
	github.com/jpillora/go-tld v1.2.1
	github.com/libp2p/go-reuseport v0.2.0
	github.com/mxschmitt/golang-combinations v1.1.0
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/refraction-networking/utls v1.1.2

)

require (
	cloud.google.com/go v0.102.1 // indirect
	cloud.google.com/go/compute v1.7.0 // indirect
	cloud.google.com/go/iam v0.3.0 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/pprof v0.0.0-20210720184732-4bb14d4b1be1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.1.0 // indirect
	github.com/googleapis/gax-go/v2 v2.5.1 // indirect
	github.com/kaorimatz/go-mrt v0.0.0-20210326003454-aa11f3646f93 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/quic-go/quic-go v0.50.1 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220909003341-f21342109be1 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
	google.golang.org/api v0.95.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220914142337-ca0e39ece12f // indirect
	google.golang.org/grpc v1.48.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace cenfuzz-advanced/quic_fuzzer => ./quic_fuzzer
