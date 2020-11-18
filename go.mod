module github.com/projectrekor/rekor

go 1.14

require (
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/trillian v1.3.10
	github.com/mitchellh/go-homedir v1.1.0
	github.com/projectrekor/rekor-server v0.0.0-20201118155434-db5416f3d9bf
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.1
	go.etcd.io/etcd v3.3.25+incompatible // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200311171314-f7b00557c8c4
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	google.golang.org/appengine v1.6.6
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
