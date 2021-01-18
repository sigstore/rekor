module github.com/projectrekor/rekor

go 1.14

require (
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/blang/semver v3.5.1+incompatible
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.19.9
	github.com/go-openapi/loads v0.20.0
	github.com/go-openapi/runtime v0.19.24
	github.com/go-openapi/spec v0.20.1
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.13
	github.com/go-openapi/validate v0.20.1
	github.com/go-swagger/go-swagger v0.25.0 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/trillian v1.3.10
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20210106175330-e54e81d562c7
	github.com/kr/pretty v0.2.1 // indirect
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mediocregopher/radix/v4 v4.0.0-beta.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/rs/cors v1.7.0
	github.com/spf13/afero v1.5.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/urfave/negroni v1.0.0
	go.etcd.io/etcd v3.3.25+incompatible // indirect
	go.uber.org/goleak v1.1.10
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/mod v0.4.1 // indirect
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58 // indirect
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
	golang.org/x/text v0.3.5 // indirect
	golang.org/x/tools v0.0.0-20210115202250-e0d201561e39 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20200825200019-8632dd797987
	google.golang.org/grpc v1.32.0
	gopkg.in/ini.v1 v1.62.0 // indirect
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
