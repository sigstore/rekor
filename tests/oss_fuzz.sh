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

apt-get update && apt-get install -y wget
cd $SRC
wget https://go.dev/dl/go1.19.5.linux-amd64.tar.gz

mkdir temp-go
rm -rf /root/.go/*
tar -C temp-go/ -xzf go1.19.5.linux-amd64.tar.gz
mv temp-go/go/* /root/.go/


cd $SRC
git clone --depth=1 https://github.com/AdamKorcz/instrumentation
cd instrumentation
go run main.go $SRC/rekor

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
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/cose FuzzCreateProposedEntry FuzzCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/alpine FuzzPackageUnmarshal FuzzPackageUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/jar FuzzJarUnmarshal FuzzJarUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/hashedrekord FuzzHashedRekord FuzzHashedRekord
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.1 FuzzIntotoCreateProposedEntry FuzzIntotoCreateProposedEntry_v001
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/intoto/v0.0.2 FuzzIntotoCreateProposedEntry FuzzIntotoCreateProposedEntry_v002
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/tuf/v0.0.1 FuzzTufCreateProposedEntry FuzzTufCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1 FuzzRfc3161CreateProposedEntry FuzzRfc3161CreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rpm/v0.0.1 FuzzRpmCreateProposedEntry FuzzRpmCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/helm/v0.0.1 FuzzHelmCreateProposedEntry FuzzHelmCreateProposedEntry
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/helm/v0.0.1 FuzzHelmProvenanceUnmarshal FuzzHelmProvenanceUnmarshal
compile_native_go_fuzzer github.com/sigstore/rekor/pkg/types/rekord/v0.0.1 FuzzRekordCreateProposedEntry FuzzRekordCreateProposedEntry

cp $SRC/rekor/tests/fuzz-testdata/*.options $OUT/
