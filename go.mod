module github.com/sigstore/rekor

go 1.22

require (
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/blang/semver v3.5.1+incompatible
	github.com/cavaliercoder/go-rpm v0.0.0-20200122174316-8cb9fd9c31a8
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.22.0
	github.com/go-openapi/loads v0.22.0
	github.com/go-openapi/runtime v0.28.0
	github.com/go-openapi/spec v0.21.0
	github.com/go-openapi/strfmt v0.23.0
	github.com/go-openapi/swag v0.23.0
	github.com/go-openapi/validate v0.24.0
	github.com/google/go-cmp v0.6.0
	github.com/google/rpmpack v0.6.0
	github.com/google/trillian v1.6.0
	github.com/in-toto/in-toto-golang v0.9.0
	github.com/jedisct1/go-minisign v0.0.0-20211028175153-1c139d1cc84b
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.19.1
	github.com/rs/cors v1.11.0
	github.com/sassoftware/relic v7.2.1+incompatible
	github.com/secure-systems-lab/go-securesystemslib v0.8.0
	github.com/sigstore/sigstore v1.8.4
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.19.0
	github.com/theupdateframework/go-tuf v0.7.0
	github.com/transparency-dev/merkle v0.0.2
	github.com/veraison/go-cose v1.2.1
	github.com/zalando/go-keyring v0.2.3 // indirect
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
	gocloud.dev v0.37.0
	golang.org/x/crypto v0.24.0
	golang.org/x/mod v0.18.0
	golang.org/x/net v0.26.0
	golang.org/x/sync v0.7.0
	google.golang.org/genproto v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/ini.v1 v1.67.0
	sigs.k8s.io/release-utils v0.8.2
	sigs.k8s.io/yaml v1.4.0
)

require (
	cloud.google.com/go/profiler v0.4.0
	cloud.google.com/go/pubsub v1.39.0
	github.com/AdamKorcz/go-fuzz-headers-1 v0.0.0-20230919221257-8b5d3ce2d11d
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/cyberphone/json-canonicalization v0.0.0-20220623050100-57a0ce2678a7
	github.com/go-redis/redismock/v9 v9.2.0
	github.com/go-sql-driver/mysql v1.8.1
	github.com/golang/mock v1.6.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/jmoiron/sqlx v1.4.0
	github.com/redis/go-redis/v9 v9.5.3
	github.com/sassoftware/relic/v7 v7.6.2
	github.com/sigstore/protobuf-specs v0.3.2
	github.com/sigstore/sigstore/pkg/signature/kms/aws v1.8.4
	github.com/sigstore/sigstore/pkg/signature/kms/azure v1.8.4
	github.com/sigstore/sigstore/pkg/signature/kms/gcp v1.8.4
	github.com/sigstore/sigstore/pkg/signature/kms/hashivault v1.8.4
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240617180043-68d350f18fd4
)

require (
	cloud.google.com/go/auth v0.5.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	cloud.google.com/go/longrunning v0.5.7 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.12.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.6.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.9.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.1.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.0.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/alessio/shellescape v1.4.1 // indirect
	github.com/aws/aws-sdk-go v1.53.10 // indirect
	github.com/aws/aws-sdk-go-v2 v1.27.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.17 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.17 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.4 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.16.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.32.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.51.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.24.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.11 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/cavaliergopher/cpio v1.0.1 // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v3 v3.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/pprof v0.0.0-20231023181126-ff6d637d2a7b // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/vault/api v1.14.0 // indirect
	github.com/jellydator/ttlcache/v3 v3.2.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240610135401-a8a62080eff3 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	k8s.io/klog/v2 v2.120.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.4.0 // indirect
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/iam v1.1.8 // indirect
	cloud.google.com/go/kms v1.17.1 // indirect
	cloud.google.com/go/storage v1.41.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cavaliercoder/badio v0.0.0-20160213150051-ce5280129e9e // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be // indirect
	github.com/danieljoos/wincred v1.2.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-containerregistry v0.19.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/google/wire v0.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/howeyc/gopass v0.0.0-20210920133722-c8aef6fb66ef // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230907030200-6d76a0f91e1e // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.mongodb.org/mongo-driver v1.14.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.step.sm/crypto v0.47.1
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/term v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/api v0.185.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
