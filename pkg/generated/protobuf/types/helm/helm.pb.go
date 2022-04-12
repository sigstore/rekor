//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.12.4
// source: pkg/types/helm/helm.proto

package helm

import (
	protobuf "github.com/sigstore/rekor/pkg/generated/protobuf"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

//
// ProposedHelmChart represents the structure of the message required to present to Rekor
// to make an entry of the HelmChart type.
type ProposedHelmChart struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Public key used to verify signed provenance file (currently PGP only)
	PublicKey *protobuf.PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	//
	// Helm chart contents (not stored in log, but needed to verify integrity of provenance)
	Chart []byte `protobuf:"bytes,2,opt,name=chart,proto3" json:"chart,omitempty"`
	//
	// Helm provenance file (this will be stored in transparency log entry)
	ProvenanceFile []byte `protobuf:"bytes,3,opt,name=provenance_file,json=provenanceFile,proto3" json:"provenance_file,omitempty"`
}

func (x *ProposedHelmChart) Reset() {
	*x = ProposedHelmChart{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_helm_helm_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposedHelmChart) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposedHelmChart) ProtoMessage() {}

func (x *ProposedHelmChart) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_helm_helm_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposedHelmChart.ProtoReflect.Descriptor instead.
func (*ProposedHelmChart) Descriptor() ([]byte, []int) {
	return file_pkg_types_helm_helm_proto_rawDescGZIP(), []int{0}
}

func (x *ProposedHelmChart) GetPublicKey() *protobuf.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *ProposedHelmChart) GetChart() []byte {
	if x != nil {
		return x.Chart
	}
	return nil
}

func (x *ProposedHelmChart) GetProvenanceFile() []byte {
	if x != nil {
		return x.ProvenanceFile
	}
	return nil
}

//
// HelmChart represents the structure of the entry persisted in the transparency log for
// the HelmChart type.
type HelmChart struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Digital signature and public key
	Signature *protobuf.Signature `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	//
	// Hash over entire helm chart
	Hash *protobuf.Hash `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *HelmChart) Reset() {
	*x = HelmChart{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_helm_helm_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HelmChart) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HelmChart) ProtoMessage() {}

func (x *HelmChart) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_helm_helm_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HelmChart.ProtoReflect.Descriptor instead.
func (*HelmChart) Descriptor() ([]byte, []int) {
	return file_pkg_types_helm_helm_proto_rawDescGZIP(), []int{1}
}

func (x *HelmChart) GetSignature() *protobuf.Signature {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *HelmChart) GetHash() *protobuf.Hash {
	if x != nil {
		return x.Hash
	}
	return nil
}

var File_pkg_types_helm_helm_proto protoreflect.FileDescriptor

var file_pkg_types_helm_helm_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x68, 0x65, 0x6c, 0x6d,
	0x2f, 0x68, 0x65, 0x6c, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x64, 0x65, 0x76,
	0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e,
	0x76, 0x32, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x68, 0x65, 0x6c, 0x6d, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f,
	0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12,
	0x72, 0x65, 0x6b, 0x6f, 0x72, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa2, 0x01, 0x0a, 0x11, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x48,
	0x65, 0x6c, 0x6d, 0x43, 0x68, 0x61, 0x72, 0x74, 0x12, 0x44, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64,
	0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f,
	0x72, 0x2e, 0x76, 0x32, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x03,
	0xe0, 0x41, 0x02, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x19,
	0x0a, 0x05, 0x63, 0x68, 0x61, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03, 0xe0,
	0x41, 0x02, 0x52, 0x05, 0x63, 0x68, 0x61, 0x72, 0x74, 0x12, 0x2c, 0x0a, 0x0f, 0x70, 0x72, 0x6f,
	0x76, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x76, 0x65, 0x6e, 0x61,
	0x6e, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x22, 0x7c, 0x0a, 0x09, 0x48, 0x65, 0x6c, 0x6d, 0x43,
	0x68, 0x61, 0x72, 0x74, 0x12, 0x3e, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69,
	0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e,
	0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x12, 0x2f, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x52,
	0x04, 0x68, 0x61, 0x73, 0x68, 0x42, 0x71, 0x0a, 0x20, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x68, 0x65, 0x6c, 0x6d, 0x42, 0x0e, 0x52, 0x65, 0x6b, 0x6f, 0x72,
	0x48, 0x65, 0x6c, 0x6d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3b, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2f, 0x68, 0x65, 0x6c, 0x6d, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_types_helm_helm_proto_rawDescOnce sync.Once
	file_pkg_types_helm_helm_proto_rawDescData = file_pkg_types_helm_helm_proto_rawDesc
)

func file_pkg_types_helm_helm_proto_rawDescGZIP() []byte {
	file_pkg_types_helm_helm_proto_rawDescOnce.Do(func() {
		file_pkg_types_helm_helm_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_types_helm_helm_proto_rawDescData)
	})
	return file_pkg_types_helm_helm_proto_rawDescData
}

var file_pkg_types_helm_helm_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_pkg_types_helm_helm_proto_goTypes = []interface{}{
	(*ProposedHelmChart)(nil),  // 0: dev.sigstore.rekor.v2.types.helm.ProposedHelmChart
	(*HelmChart)(nil),          // 1: dev.sigstore.rekor.v2.types.helm.HelmChart
	(*protobuf.PublicKey)(nil), // 2: dev.sigstore.rekor.v2.PublicKey
	(*protobuf.Signature)(nil), // 3: dev.sigstore.rekor.v2.Signature
	(*protobuf.Hash)(nil),      // 4: dev.sigstore.rekor.v2.Hash
}
var file_pkg_types_helm_helm_proto_depIdxs = []int32{
	2, // 0: dev.sigstore.rekor.v2.types.helm.ProposedHelmChart.public_key:type_name -> dev.sigstore.rekor.v2.PublicKey
	3, // 1: dev.sigstore.rekor.v2.types.helm.HelmChart.signature:type_name -> dev.sigstore.rekor.v2.Signature
	4, // 2: dev.sigstore.rekor.v2.types.helm.HelmChart.hash:type_name -> dev.sigstore.rekor.v2.Hash
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_pkg_types_helm_helm_proto_init() }
func file_pkg_types_helm_helm_proto_init() {
	if File_pkg_types_helm_helm_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_types_helm_helm_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposedHelmChart); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_types_helm_helm_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HelmChart); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_types_helm_helm_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_types_helm_helm_proto_goTypes,
		DependencyIndexes: file_pkg_types_helm_helm_proto_depIdxs,
		MessageInfos:      file_pkg_types_helm_helm_proto_msgTypes,
	}.Build()
	File_pkg_types_helm_helm_proto = out.File
	file_pkg_types_helm_helm_proto_rawDesc = nil
	file_pkg_types_helm_helm_proto_goTypes = nil
	file_pkg_types_helm_helm_proto_depIdxs = nil
}
