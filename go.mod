module github.com/theairblow/turnable

go 1.25.0

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/pion/dtls/v3 v3.1.2
	github.com/pion/logging v0.2.4
	github.com/pion/sctp v1.9.4
	github.com/pion/sdp/v3 v3.0.18
	github.com/pion/turn/v5 v5.0.3
	github.com/spf13/cobra v1.10.2
	github.com/xtaci/kcp-go/v5 v5.6.72
	github.com/xtaci/smux v1.5.57
	golang.org/x/net v0.53.0
)

// fixes building on android locally inside termux
replace github.com/wlynxg/anet => github.com/BieHDC/anet v0.0.6-0.20241226223613-d47f8b766b3c

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.3 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.1.2 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
