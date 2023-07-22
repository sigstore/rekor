#!/bin/bash
#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# remove e2e build comments. 
# This is a temporary fix.
# TODO AdamKorcz: Get rid of these sed commands
sed -i '16,17d' $SRC/rekor/pkg/pki/x509/e2e.go
sed -i '16d' $SRC/rekor/pkg/util/util.go

cd $SRC/rekor
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/sigstore/rekor/pkg/pki FuzzKeys FuzzKeys
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzCreateEntryIDFromParts FuzzCreateEntryIDFromParts
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzGetUUIDFromIDString FuzzGetUUIDFromIDString
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzGetTreeIDFromIDString FuzzGetTreeIDFromIDString
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzPadToTreeIDLen FuzzPadToTreeIDLen
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzReturnEntryIDString FuzzReturnEntryIDString
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzTreeID FuzzTreeID
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzValidateUUID FuzzValidateUUID
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzValidateTreeID FuzzValidateTreeID
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/sharding FuzzValidateEntryID FuzzValidateEntryID
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/signer FuzzNewFile FuzzNewFile
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/cose/v0.0.1 FuzzCoseCreateProposedEntry FuzzCoseCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/cose/v0.0.1 FuzzCoseUnmarshalAndCanonicalize FuzzCoseUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/hashedrekord FuzzHashedRekord FuzzHashedRekord
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1 FuzzHashedRekordCreateProposedEntry FuzzHashedRekordCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1 FuzzHashedRekordUnmarshalAndCanonicalize FuzzHashedRekordUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/alpine FuzzPackageUnmarshal FuzzPackageUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/alpine/v0.0.1 FuzzAlpineCreateProposedEntry FuzzAlpineCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/alpine/v0.0.1 FuzzAlpineUnmarshalAndCanonicalize FuzzAlpineUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/jar FuzzJarUnmarshal FuzzJarUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/jar/v0.0.1 FuzzJarCreateProposedEntry FuzzJarCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/jar/v0.0.1 FuzzJarUnmarshalAndCanonicalize FuzzJarUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.1 FuzzIntotoCreateProposedEntry FuzzIntotoCreateProposedEntry_v001
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.1 FuzzIntotoUnmarshalAndCanonicalize FuzzIntotoUnmarshalAndCanonicalize_v001
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.2 FuzzIntotoCreateProposedEntry FuzzIntotoCreateProposedEntry_v002
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.2 FuzzIntotoUnmarshalAndCanonicalize FuzzIntotoUnmarshalAndCanonicalize_v002
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/tuf/v0.0.1 FuzzTufCreateProposedEntry FuzzTufCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/tuf/v0.0.1 FuzzTufUnmarshalAndCanonicalize FuzzTufUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1 FuzzRfc3161CreateProposedEntry FuzzRfc3161CreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1 FuzzRfc3161UnmarshalAndCanonicalize FuzzRfc3161UnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rpm/v0.0.1 FuzzRpmCreateProposedEntry FuzzRpmCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rpm/v0.0.1 FuzzRpmUnmarshalAndCanonicalize FuzzRpmUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/helm/v0.0.1 FuzzHelmCreateProposedEntry FuzzHelmCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/helm/v0.0.1 FuzzHelmUnmarshalAndCanonicalize FuzzHelmUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/helm/v0.0.1 FuzzHelmProvenanceUnmarshal FuzzHelmProvenanceUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rekord/v0.0.1 FuzzRekordCreateProposedEntry FuzzRekordCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rekord/v0.0.1 FuzzRekordUnmarshalAndCanonicalize FuzzRekordUnmarshalAndCanonicalize
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/dsse/v0.0.1 FuzzDSSECreateProposedEntry FuzzDSSECreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/dsse/v0.0.1 FuzzDSSEUnmarshalAndCanonicalize FuzzDSSEUnmarshalAndCanonicalize

# Test 3rd party API that rekor/pkg/types/jar/v0.0.1 uses
go mod edit -replace github.com/sassoftware/relic=$SRC/relic
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/jar/v0.0.1 FuzzJarutilsVerify FuzzJarutilsVerify 


cp $SRC/rekor/tests/fuzz-testdata/*.options $OUT/
zip $OUT/FuzzPackageUnmarshal_seed_corpus.zip $SRC/rekor/tests/fuzz-testdata/seeds/alpine/FuzzPackageUnmarshal/FuzzPackageUnmarshal_seed1
