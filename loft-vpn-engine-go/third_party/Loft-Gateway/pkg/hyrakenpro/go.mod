module loft.local/hyrakenpro

go 1.26.0

toolchain go1.27.4

require (
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	loft.local/hydra v0.0.0
	loft.local/trafficprofile v0.0.0
)

require golang.org/x/text v0.43.0 // indirect

replace loft.local/trafficprofile => ../trafficprofile

replace loft.local/hydra => ../../modules/firewall/hydra
