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
// source: pkg/types/rpm/rpm.proto

package rpm

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
// ProposedRPMPackage represents the structure of the message required to present to Rekor
// to make an entry of the RPMPackage type.
type ProposedRPMPackage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Public key (currently only PGP supported)
	PublicKey *protobuf.PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	//
	// RPM package which contains an embedded signature (this will not be persisted into the log)
	Content []byte `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *ProposedRPMPackage) Reset() {
	*x = ProposedRPMPackage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_rpm_rpm_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposedRPMPackage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposedRPMPackage) ProtoMessage() {}

func (x *ProposedRPMPackage) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_rpm_rpm_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposedRPMPackage.ProtoReflect.Descriptor instead.
func (*ProposedRPMPackage) Descriptor() ([]byte, []int) {
	return file_pkg_types_rpm_rpm_proto_rawDescGZIP(), []int{0}
}

func (x *ProposedRPMPackage) GetPublicKey() *protobuf.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *ProposedRPMPackage) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

//
// RPMPackage represents the structure of the entry persisted in the transparency log for
// the RPMPackage type.
type RPMPackage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Digital signature and public key
	Signature *protobuf.Signature `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	//
	// Hash over entire RPM package
	Hash *protobuf.Hash `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	//
	// Key / value pairs from RPM headers
	Headers map[string]string `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *RPMPackage) Reset() {
	*x = RPMPackage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_rpm_rpm_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RPMPackage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RPMPackage) ProtoMessage() {}

func (x *RPMPackage) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_rpm_rpm_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RPMPackage.ProtoReflect.Descriptor instead.
func (*RPMPackage) Descriptor() ([]byte, []int) {
	return file_pkg_types_rpm_rpm_proto_rawDescGZIP(), []int{1}
}

func (x *RPMPackage) GetSignature() *protobuf.Signature {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *RPMPackage) GetHash() *protobuf.Hash {
	if x != nil {
		return x.Hash
	}
	return nil
}

func (x *RPMPackage) GetHeaders() map[string]string {
	if x != nil {
		return x.Headers
	}
	return nil
}

var File_pkg_types_rpm_rpm_proto protoreflect.FileDescriptor

var file_pkg_types_rpm_rpm_proto_rawDesc = []byte{
	0x0a, 0x17, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x72, 0x70, 0x6d, 0x2f,
	0x72, 0x70, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x64, 0x65, 0x76, 0x2e, 0x73,
	0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32,
	0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x72, 0x70, 0x6d, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68,
	0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x72, 0x65, 0x6b,
	0x6f, 0x72, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x79, 0x0a, 0x12, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x52, 0x50, 0x4d, 0x50, 0x61,
	0x63, 0x6b, 0x61, 0x67, 0x65, 0x12, 0x44, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64, 0x65, 0x76, 0x2e,
	0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76,
	0x32, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x03, 0xe0, 0x41, 0x02,
	0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x0a, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03, 0xe0, 0x41,
	0x02, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x8d, 0x02, 0x0a, 0x0a, 0x52,
	0x50, 0x4d, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x12, 0x3e, 0x0a, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64,
	0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f,
	0x72, 0x2e, 0x76, 0x32, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x2f, 0x0a, 0x04, 0x68, 0x61, 0x73,
	0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69,
	0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e,
	0x48, 0x61, 0x73, 0x68, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x52, 0x0a, 0x07, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x64, 0x65,
	0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72,
	0x2e, 0x76, 0x32, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x72, 0x70, 0x6d, 0x2e, 0x52, 0x50,
	0x4d, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x1a, 0x3a,
	0x0a, 0x0c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x6e, 0x0a, 0x1f, 0x64, 0x65,
	0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72,
	0x2e, 0x76, 0x32, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x72, 0x70, 0x6d, 0x42, 0x0d, 0x52,
	0x65, 0x6b, 0x6f, 0x72, 0x52, 0x50, 0x4d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3a,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74,
	0x6f, 0x72, 0x65, 0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x72, 0x70, 0x6d, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_pkg_types_rpm_rpm_proto_rawDescOnce sync.Once
	file_pkg_types_rpm_rpm_proto_rawDescData = file_pkg_types_rpm_rpm_proto_rawDesc
)

func file_pkg_types_rpm_rpm_proto_rawDescGZIP() []byte {
	file_pkg_types_rpm_rpm_proto_rawDescOnce.Do(func() {
		file_pkg_types_rpm_rpm_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_types_rpm_rpm_proto_rawDescData)
	})
	return file_pkg_types_rpm_rpm_proto_rawDescData
}

var file_pkg_types_rpm_rpm_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_pkg_types_rpm_rpm_proto_goTypes = []interface{}{
	(*ProposedRPMPackage)(nil), // 0: dev.sigstore.rekor.v2.types.rpm.ProposedRPMPackage
	(*RPMPackage)(nil),         // 1: dev.sigstore.rekor.v2.types.rpm.RPMPackage
	nil,                        // 2: dev.sigstore.rekor.v2.types.rpm.RPMPackage.HeadersEntry
	(*protobuf.PublicKey)(nil), // 3: dev.sigstore.rekor.v2.PublicKey
	(*protobuf.Signature)(nil), // 4: dev.sigstore.rekor.v2.Signature
	(*protobuf.Hash)(nil),      // 5: dev.sigstore.rekor.v2.Hash
}
var file_pkg_types_rpm_rpm_proto_depIdxs = []int32{
	3, // 0: dev.sigstore.rekor.v2.types.rpm.ProposedRPMPackage.public_key:type_name -> dev.sigstore.rekor.v2.PublicKey
	4, // 1: dev.sigstore.rekor.v2.types.rpm.RPMPackage.signature:type_name -> dev.sigstore.rekor.v2.Signature
	5, // 2: dev.sigstore.rekor.v2.types.rpm.RPMPackage.hash:type_name -> dev.sigstore.rekor.v2.Hash
	2, // 3: dev.sigstore.rekor.v2.types.rpm.RPMPackage.headers:type_name -> dev.sigstore.rekor.v2.types.rpm.RPMPackage.HeadersEntry
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_pkg_types_rpm_rpm_proto_init() }
func file_pkg_types_rpm_rpm_proto_init() {
	if File_pkg_types_rpm_rpm_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_types_rpm_rpm_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposedRPMPackage); i {
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
		file_pkg_types_rpm_rpm_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RPMPackage); i {
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
			RawDescriptor: file_pkg_types_rpm_rpm_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_types_rpm_rpm_proto_goTypes,
		DependencyIndexes: file_pkg_types_rpm_rpm_proto_depIdxs,
		MessageInfos:      file_pkg_types_rpm_rpm_proto_msgTypes,
	}.Build()
	File_pkg_types_rpm_rpm_proto = out.File
	file_pkg_types_rpm_rpm_proto_rawDesc = nil
	file_pkg_types_rpm_rpm_proto_goTypes = nil
	file_pkg_types_rpm_rpm_proto_depIdxs = nil
}
