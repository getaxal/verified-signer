module github.com/axal/verified-signer-host

go 1.23.9

require (
	github.com/axal/verified-signer-common v0.0.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/BurntSushi/toml v1.2.0 // indirect
	github.com/jinzhu/configor v1.2.2 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/axal/verified-signer-common => ../common
