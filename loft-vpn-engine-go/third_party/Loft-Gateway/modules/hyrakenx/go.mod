module loft.local/hyrakenx

go 1.26.0

toolchain go1.27.4

require (
 loft.local/hydra v0.0.0
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.7
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/andybalholm/brotli v1.2.7 // indirect
	github.com/klauspost/compress v1.20.2 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/net v0.62.0 // indirect
)

replace github.com/sagernet/quic-go => ../../pkg/hyrakenquic

replace loft.local/hydra => ../firewall/hydra
