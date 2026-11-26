module net.aptist.loft/loft-vpn-engine-go

go 1.27.4

require (
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1
	github.com/sagernet/sing v0.9.6-0.20260922013354-87c33f17688f
	github.com/sagernet/sing-tun v0.9.6-0.20260924001923-ddaa4ca25e3b
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	loft.local/ghostx-core v0.0.0
	loft.local/hydra v0.0.0
	loft.local/hyrakenpro v0.0.0
	loft.local/hyrakenx v0.0.0
	loft.local/trafficprofile v0.0.0
)

require (
	github.com/andybalholm/brotli v1.2.7 // indirect
	github.com/florianl/go-nfqueue/v2 v2.1.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/klauspost/compress v1.20.2 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-mod.4 // indirect
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.7 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
)

replace loft.local/hyrakenx => ./third_party/Loft-Gateway/modules/hyrakenx

replace loft.local/hyrakenpro => ./third_party/Loft-Gateway/pkg/hyrakenpro

replace loft.local/hydra => ./third_party/Loft-Gateway/modules/firewall/hydra

replace loft.local/trafficprofile => ./third_party/Loft-Gateway/pkg/trafficprofile

replace github.com/sagernet/quic-go => ./third_party/Loft-Gateway/pkg/hyrakenquic

replace loft.local/ghostx-core => ./third_party/Loft-Gateway/GhostX-core-main

replace github.com/sagernet/sing-tun => ./third_party/sing-tun

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
