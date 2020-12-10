module github.com/projectrekor/rekor

go 1.14

require (
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.19.9
	github.com/go-openapi/loads v0.19.7
	github.com/go-openapi/runtime v0.19.24
	github.com/go-openapi/spec v0.19.15
	github.com/go-openapi/strfmt v0.19.11
	github.com/go-openapi/swag v0.19.12
	github.com/go-openapi/validate v0.19.15
	github.com/golang/protobuf v1.4.2
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/trillian v1.3.10
	github.com/mitchellh/go-homedir v1.1.0
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/tidwall/sjson v1.1.2
	go.etcd.io/etcd v3.3.25+incompatible // indirect
	go.uber.org/goleak v1.1.10
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	google.golang.org/appengine v1.6.6
	google.golang.org/grpc v1.32.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
