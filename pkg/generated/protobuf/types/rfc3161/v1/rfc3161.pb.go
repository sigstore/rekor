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
// source: pkg/types/rfc3161/v1/rfc3161.proto

package v1

import (
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
// ProposedTimestampResponse represents the structure of the message required to present to Rekor
// to make an entry of the TimestampResponse type.
//
// TimestampResponse uses an identical input and output format;
// we create both for potential forward compatibility of separating and changing them;
// this also makes the assignment more explicit
type ProposedTimestampResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Timestamp request in binary format according to RFC3161
	Content []byte `protobuf:"bytes,1,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *ProposedTimestampResponse) Reset() {
	*x = ProposedTimestampResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposedTimestampResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposedTimestampResponse) ProtoMessage() {}

func (x *ProposedTimestampResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposedTimestampResponse.ProtoReflect.Descriptor instead.
func (*ProposedTimestampResponse) Descriptor() ([]byte, []int) {
	return file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescGZIP(), []int{0}
}

func (x *ProposedTimestampResponse) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

//
// TimestampResponse represents the structure of the entry persisted in the transparency log for
// the TimestampResponse type.
type TimestampResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Timestamp response in binary format according to RFC3161
	Content []byte `protobuf:"bytes,1,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *TimestampResponse) Reset() {
	*x = TimestampResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TimestampResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TimestampResponse) ProtoMessage() {}

func (x *TimestampResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TimestampResponse.ProtoReflect.Descriptor instead.
func (*TimestampResponse) Descriptor() ([]byte, []int) {
	return file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescGZIP(), []int{1}
}

func (x *TimestampResponse) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

var File_pkg_types_rfc3161_v1_rfc3161_proto protoreflect.FileDescriptor

var file_pkg_types_rfc3161_v1_rfc3161_proto_rawDesc = []byte{
	0x0a, 0x22, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x72, 0x66, 0x63, 0x33,
	0x31, 0x36, 0x31, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x66, 0x63, 0x33, 0x31, 0x36, 0x31, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x23, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x72,
	0x66, 0x63, 0x33, 0x31, 0x36, 0x31, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61,
	0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3a, 0x0a, 0x19, 0x50, 0x72,
	0x6f, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x2d, 0x0a, 0x11, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x42, 0x7a, 0x0a, 0x23, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x72, 0x66, 0x63, 0x33, 0x31, 0x36, 0x31, 0x2e, 0x76, 0x31, 0x42, 0x0e, 0x52, 0x46,
	0x43, 0x33, 0x31, 0x36, 0x31, 0x56, 0x31, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x41,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74,
	0x6f, 0x72, 0x65, 0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x72, 0x66, 0x63, 0x33, 0x31, 0x36, 0x31, 0x2f, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescOnce sync.Once
	file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescData = file_pkg_types_rfc3161_v1_rfc3161_proto_rawDesc
)

func file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescGZIP() []byte {
	file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescOnce.Do(func() {
		file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescData)
	})
	return file_pkg_types_rfc3161_v1_rfc3161_proto_rawDescData
}

var file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_pkg_types_rfc3161_v1_rfc3161_proto_goTypes = []interface{}{
	(*ProposedTimestampResponse)(nil), // 0: dev.sigstore.rekor.types.rfc3161.v1.ProposedTimestampResponse
	(*TimestampResponse)(nil),         // 1: dev.sigstore.rekor.types.rfc3161.v1.TimestampResponse
}
var file_pkg_types_rfc3161_v1_rfc3161_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pkg_types_rfc3161_v1_rfc3161_proto_init() }
func file_pkg_types_rfc3161_v1_rfc3161_proto_init() {
	if File_pkg_types_rfc3161_v1_rfc3161_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposedTimestampResponse); i {
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
		file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TimestampResponse); i {
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
			RawDescriptor: file_pkg_types_rfc3161_v1_rfc3161_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_types_rfc3161_v1_rfc3161_proto_goTypes,
		DependencyIndexes: file_pkg_types_rfc3161_v1_rfc3161_proto_depIdxs,
		MessageInfos:      file_pkg_types_rfc3161_v1_rfc3161_proto_msgTypes,
	}.Build()
	File_pkg_types_rfc3161_v1_rfc3161_proto = out.File
	file_pkg_types_rfc3161_v1_rfc3161_proto_rawDesc = nil
	file_pkg_types_rfc3161_v1_rfc3161_proto_goTypes = nil
	file_pkg_types_rfc3161_v1_rfc3161_proto_depIdxs = nil
}
