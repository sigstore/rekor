module github.com/sigstore/rekor

go 1.18

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/blang/semver v3.5.1+incompatible
	github.com/cavaliercoder/go-rpm v0.0.0-20200122174316-8cb9fd9c31a8
	github.com/cyberphone/json-canonicalization v0.0.0-20210303052042-6bc126869bf4
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.20.3
	github.com/go-openapi/loads v0.21.2
	github.com/go-openapi/runtime v0.25.0
	github.com/go-openapi/spec v0.20.8
	github.com/go-openapi/strfmt v0.21.3
	github.com/go-openapi/swag v0.22.3
	github.com/go-openapi/validate v0.22.1
	github.com/go-playground/validator/v10 v10.11.2
	github.com/google/go-cmp v0.5.9
	github.com/google/rpmpack v0.0.0-20210518075352-dc539ef4f2ea
	github.com/google/trillian v1.5.1
	github.com/in-toto/in-toto-golang v0.3.4-0.20211211042327-af1f9fb822bf
	github.com/jedisct1/go-minisign v0.0.0-20211028175153-1c139d1cc84b
	github.com/mediocregopher/radix/v4 v4.1.2
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.14.0
	github.com/rs/cors v1.8.3
	github.com/sassoftware/relic v0.0.0-20210427151427-dfb082b79b74
	github.com/secure-systems-lab/go-securesystemslib v0.4.0
	github.com/sigstore/sigstore v1.5.1
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.15.0
	github.com/tent/canonical-json-go v0.0.0-20130607151641-96e4ba3a7613
	github.com/theupdateframework/go-tuf v0.5.2-0.20220930112810-3890c1e7ace4
	github.com/transparency-dev/merkle v0.0.1
	github.com/veraison/go-cose v1.0.0
	github.com/zalando/go-keyring v0.1.1 // indirect
	go.uber.org/goleak v1.2.0
	go.uber.org/zap v1.24.0
	gocloud.dev v0.24.1-0.20211119014450-028788aaaa4c
	golang.org/x/crypto v0.5.0
	golang.org/x/mod v0.7.0
	golang.org/x/net v0.5.0
	golang.org/x/sync v0.1.0
	google.golang.org/genproto v0.0.0-20221227171554-f9683d7f8bef
	google.golang.org/grpc v1.52.3
	google.golang.org/protobuf v1.28.1
	gopkg.in/ini.v1 v1.67.0
	sigs.k8s.io/release-utils v0.7.3
)

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230106234847-43070de90fa1
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-retryablehttp v0.7.2
	golang.org/x/exp v0.0.0-20220823124025-807a23277127
)

require (
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/otel v1.11.1 // indirect
	go.opentelemetry.io/otel/trace v1.11.1 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
)

require (
	cloud.google.com/go v0.107.0 // indirect
	cloud.google.com/go/compute v1.14.0 // indirect
	cloud.google.com/go/iam v0.8.0 // indirect
	cloud.google.com/go/kms v1.8.0 // indirect
	cloud.google.com/go/storage v1.27.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cavaliercoder/badio v0.0.0-20160213150051-ce5280129e9e // indirect
	github.com/cavaliercoder/go-cpio v0.0.0-20180626203310-925f9528c45e // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be // indirect
	github.com/danieljoos/wincred v1.1.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/go-openapi/analysis v0.21.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/godbus/dbus/v5 v5.0.4 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-containerregistry v0.12.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.1 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jellydator/ttlcache/v2 v2.11.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/letsencrypt/boulder v0.0.0-20221109233200-85aa52084eaf // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tilinna/clock v1.1.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.mongodb.org/mongo-driver v1.10.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.step.sm/crypto v0.24.0
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/term v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.109.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdaLogics/go-fuzz-headers => github.com/AdamKorcz/go-fuzz-headers-1 v0.0.0-20230201144411-22e92b796899
