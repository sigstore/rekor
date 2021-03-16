module github.com/sigstore/rekor

go 1.14

require (
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/blang/semver v3.5.1+incompatible
	github.com/cavaliercoder/badio v0.0.0-20160213150051-ce5280129e9e // indirect
	github.com/cavaliercoder/go-rpm v0.0.0-20200122174316-8cb9fd9c31a8
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.20.0
	github.com/go-openapi/loads v0.20.2
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/spec v0.20.3
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/go-openapi/validate v0.20.2
	github.com/golang/protobuf v1.4.3
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/rpmpack v0.0.0-20210107155803-d6befbf05148
	github.com/google/trillian v1.3.13
	github.com/jedisct1/go-minisign v0.0.0-20210106175330-e54e81d562c7
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mediocregopher/radix/v4 v4.0.0-beta.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/rs/cors v1.7.0
	github.com/spf13/afero v1.5.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/urfave/negroni v1.0.0
	go.uber.org/goleak v1.1.10
	go.uber.org/zap v1.16.0
	gocloud.dev v0.22.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/mod v0.4.1 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	golang.org/x/sys v0.0.0-20210301091718-77cc2087c03b // indirect
	golang.org/x/tools v0.1.0 // indirect
	google.golang.org/genproto v0.0.0-20201203001206-6486ece9c497
	google.golang.org/grpc v1.36.0
	gopkg.in/ini.v1 v1.62.0 // indirect
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
