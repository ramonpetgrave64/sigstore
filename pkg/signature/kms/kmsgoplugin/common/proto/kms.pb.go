// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.2
// source: proto/kms.proto

package proto

import (
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

type SetStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyResourceId string `protobuf:"bytes,1,opt,name=key_resource_id,json=keyResourceId,proto3" json:"key_resource_id,omitempty"`
	HashFuncData  []byte `protobuf:"bytes,2,opt,name=hash_func_data,json=hashFuncData,proto3" json:"hash_func_data,omitempty"`
}

func (x *SetStateRequest) Reset() {
	*x = SetStateRequest{}
	mi := &file_proto_kms_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SetStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetStateRequest) ProtoMessage() {}

func (x *SetStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetStateRequest.ProtoReflect.Descriptor instead.
func (*SetStateRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{0}
}

func (x *SetStateRequest) GetKeyResourceId() string {
	if x != nil {
		return x.KeyResourceId
	}
	return ""
}

func (x *SetStateRequest) GetHashFuncData() []byte {
	if x != nil {
		return x.HashFuncData
	}
	return nil
}

type SetStateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SetStateResponse) Reset() {
	*x = SetStateResponse{}
	mi := &file_proto_kms_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SetStateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetStateResponse) ProtoMessage() {}

func (x *SetStateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetStateResponse.ProtoReflect.Descriptor instead.
func (*SetStateResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{1}
}

type SupportedAlgorithmsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SupportedAlgorithmsRequest) Reset() {
	*x = SupportedAlgorithmsRequest{}
	mi := &file_proto_kms_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SupportedAlgorithmsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SupportedAlgorithmsRequest) ProtoMessage() {}

func (x *SupportedAlgorithmsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SupportedAlgorithmsRequest.ProtoReflect.Descriptor instead.
func (*SupportedAlgorithmsRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{2}
}

type SupportedAlgorithmsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SupportedAlgorithms []string `protobuf:"bytes,1,rep,name=supported_algorithms,json=supportedAlgorithms,proto3" json:"supported_algorithms,omitempty"`
}

func (x *SupportedAlgorithmsResponse) Reset() {
	*x = SupportedAlgorithmsResponse{}
	mi := &file_proto_kms_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SupportedAlgorithmsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SupportedAlgorithmsResponse) ProtoMessage() {}

func (x *SupportedAlgorithmsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SupportedAlgorithmsResponse.ProtoReflect.Descriptor instead.
func (*SupportedAlgorithmsResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{3}
}

func (x *SupportedAlgorithmsResponse) GetSupportedAlgorithms() []string {
	if x != nil {
		return x.SupportedAlgorithms
	}
	return nil
}

type DefaultAlgorithmRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DefaultAlgorithmRequest) Reset() {
	*x = DefaultAlgorithmRequest{}
	mi := &file_proto_kms_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DefaultAlgorithmRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DefaultAlgorithmRequest) ProtoMessage() {}

func (x *DefaultAlgorithmRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DefaultAlgorithmRequest.ProtoReflect.Descriptor instead.
func (*DefaultAlgorithmRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{4}
}

type DefaultAlgorithmResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DefaultAgorithm string `protobuf:"bytes,1,opt,name=default_agorithm,json=defaultAgorithm,proto3" json:"default_agorithm,omitempty"`
}

func (x *DefaultAlgorithmResponse) Reset() {
	*x = DefaultAlgorithmResponse{}
	mi := &file_proto_kms_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DefaultAlgorithmResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DefaultAlgorithmResponse) ProtoMessage() {}

func (x *DefaultAlgorithmResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DefaultAlgorithmResponse.ProtoReflect.Descriptor instead.
func (*DefaultAlgorithmResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{5}
}

func (x *DefaultAlgorithmResponse) GetDefaultAgorithm() string {
	if x != nil {
		return x.DefaultAgorithm
	}
	return ""
}

type CreateKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algorithm string `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (x *CreateKeyRequest) Reset() {
	*x = CreateKeyRequest{}
	mi := &file_proto_kms_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyRequest) ProtoMessage() {}

func (x *CreateKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyRequest.ProtoReflect.Descriptor instead.
func (*CreateKeyRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{6}
}

func (x *CreateKeyRequest) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

type CreateKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKeyData []byte `protobuf:"bytes,1,opt,name=public_key_data,json=publicKeyData,proto3" json:"public_key_data,omitempty"`
}

func (x *CreateKeyResponse) Reset() {
	*x = CreateKeyResponse{}
	mi := &file_proto_kms_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateKeyResponse) ProtoMessage() {}

func (x *CreateKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateKeyResponse.ProtoReflect.Descriptor instead.
func (*CreateKeyResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{7}
}

func (x *CreateKeyResponse) GetPublicKeyData() []byte {
	if x != nil {
		return x.PublicKeyData
	}
	return nil
}

type SignMessageRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message     []byte       `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	SignOptions *SignOptions `protobuf:"bytes,2,opt,name=sign_options,json=signOptions,proto3" json:"sign_options,omitempty"`
}

func (x *SignMessageRequest) Reset() {
	*x = SignMessageRequest{}
	mi := &file_proto_kms_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignMessageRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignMessageRequest) ProtoMessage() {}

func (x *SignMessageRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignMessageRequest.ProtoReflect.Descriptor instead.
func (*SignMessageRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{8}
}

func (x *SignMessageRequest) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *SignMessageRequest) GetSignOptions() *SignOptions {
	if x != nil {
		return x.SignOptions
	}
	return nil
}

type SignMessageResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *SignMessageResponse) Reset() {
	*x = SignMessageResponse{}
	mi := &file_proto_kms_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignMessageResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignMessageResponse) ProtoMessage() {}

func (x *SignMessageResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignMessageResponse.ProtoReflect.Descriptor instead.
func (*SignMessageResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{9}
}

func (x *SignMessageResponse) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type VerifySignatureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature     []byte        `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	Message       []byte        `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	VerifyOptions *VerifyOption `protobuf:"bytes,3,opt,name=verify_options,json=verifyOptions,proto3" json:"verify_options,omitempty"`
}

func (x *VerifySignatureRequest) Reset() {
	*x = VerifySignatureRequest{}
	mi := &file_proto_kms_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifySignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifySignatureRequest) ProtoMessage() {}

func (x *VerifySignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifySignatureRequest.ProtoReflect.Descriptor instead.
func (*VerifySignatureRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{10}
}

func (x *VerifySignatureRequest) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *VerifySignatureRequest) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *VerifySignatureRequest) GetVerifyOptions() *VerifyOption {
	if x != nil {
		return x.VerifyOptions
	}
	return nil
}

type VerifySignatureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *VerifySignatureResponse) Reset() {
	*x = VerifySignatureResponse{}
	mi := &file_proto_kms_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifySignatureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifySignatureResponse) ProtoMessage() {}

func (x *VerifySignatureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifySignatureResponse.ProtoReflect.Descriptor instead.
func (*VerifySignatureResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{11}
}

type PublicKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PublicKeyRequest) Reset() {
	*x = PublicKeyRequest{}
	mi := &file_proto_kms_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeyRequest) ProtoMessage() {}

func (x *PublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeyRequest.ProtoReflect.Descriptor instead.
func (*PublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{12}
}

type PublicKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKeyData []byte `protobuf:"bytes,1,opt,name=public_key_data,json=publicKeyData,proto3" json:"public_key_data,omitempty"`
}

func (x *PublicKeyResponse) Reset() {
	*x = PublicKeyResponse{}
	mi := &file_proto_kms_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeyResponse) ProtoMessage() {}

func (x *PublicKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeyResponse.ProtoReflect.Descriptor instead.
func (*PublicKeyResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{13}
}

func (x *PublicKeyResponse) GetPublicKeyData() []byte {
	if x != nil {
		return x.PublicKeyData
	}
	return nil
}

type CryptoSignerRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CryptoSignerRequest) Reset() {
	*x = CryptoSignerRequest{}
	mi := &file_proto_kms_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CryptoSignerRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CryptoSignerRequest) ProtoMessage() {}

func (x *CryptoSignerRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CryptoSignerRequest.ProtoReflect.Descriptor instead.
func (*CryptoSignerRequest) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{14}
}

type CryptoSignerResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CryptoSignerResponse) Reset() {
	*x = CryptoSignerResponse{}
	mi := &file_proto_kms_proto_msgTypes[15]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CryptoSignerResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CryptoSignerResponse) ProtoMessage() {}

func (x *CryptoSignerResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[15]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CryptoSignerResponse.ProtoReflect.Descriptor instead.
func (*CryptoSignerResponse) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{15}
}

type SignOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MessageOption *MessageOption `protobuf:"bytes,1,opt,name=message_option,json=messageOption,proto3" json:"message_option,omitempty"`
}

func (x *SignOptions) Reset() {
	*x = SignOptions{}
	mi := &file_proto_kms_proto_msgTypes[16]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignOptions) ProtoMessage() {}

func (x *SignOptions) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[16]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignOptions.ProtoReflect.Descriptor instead.
func (*SignOptions) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{16}
}

func (x *SignOptions) GetMessageOption() *MessageOption {
	if x != nil {
		return x.MessageOption
	}
	return nil
}

type VerifyOption struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MessageOption *MessageOption `protobuf:"bytes,1,opt,name=message_option,json=messageOption,proto3" json:"message_option,omitempty"`
}

func (x *VerifyOption) Reset() {
	*x = VerifyOption{}
	mi := &file_proto_kms_proto_msgTypes[17]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifyOption) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyOption) ProtoMessage() {}

func (x *VerifyOption) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[17]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyOption.ProtoReflect.Descriptor instead.
func (*VerifyOption) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{17}
}

func (x *VerifyOption) GetMessageOption() *MessageOption {
	if x != nil {
		return x.MessageOption
	}
	return nil
}

type MessageOption struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DigestData []byte      `protobuf:"bytes,1,opt,name=digest_data,json=digestData,proto3" json:"digest_data,omitempty"`
	SignerOpts *SignerOpts `protobuf:"bytes,2,opt,name=signer_opts,json=signerOpts,proto3" json:"signer_opts,omitempty"`
}

func (x *MessageOption) Reset() {
	*x = MessageOption{}
	mi := &file_proto_kms_proto_msgTypes[18]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MessageOption) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageOption) ProtoMessage() {}

func (x *MessageOption) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[18]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageOption.ProtoReflect.Descriptor instead.
func (*MessageOption) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{18}
}

func (x *MessageOption) GetDigestData() []byte {
	if x != nil {
		return x.DigestData
	}
	return nil
}

func (x *MessageOption) GetSignerOpts() *SignerOpts {
	if x != nil {
		return x.SignerOpts
	}
	return nil
}

type SignerOpts struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HashFuncData []byte `protobuf:"bytes,1,opt,name=hash_func_data,json=hashFuncData,proto3" json:"hash_func_data,omitempty"`
}

func (x *SignerOpts) Reset() {
	*x = SignerOpts{}
	mi := &file_proto_kms_proto_msgTypes[19]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignerOpts) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignerOpts) ProtoMessage() {}

func (x *SignerOpts) ProtoReflect() protoreflect.Message {
	mi := &file_proto_kms_proto_msgTypes[19]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignerOpts.ProtoReflect.Descriptor instead.
func (*SignerOpts) Descriptor() ([]byte, []int) {
	return file_proto_kms_proto_rawDescGZIP(), []int{19}
}

func (x *SignerOpts) GetHashFuncData() []byte {
	if x != nil {
		return x.HashFuncData
	}
	return nil
}

var File_proto_kms_proto protoreflect.FileDescriptor

var file_proto_kms_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6b, 0x6d, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x03, 0x6b, 0x6d, 0x73, 0x22, 0x5f, 0x0a, 0x0f, 0x53, 0x65, 0x74, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x0f, 0x6b, 0x65, 0x79,
	0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x6b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49,
	0x64, 0x12, 0x24, 0x0a, 0x0e, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x5f, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x68, 0x61, 0x73, 0x68, 0x46,
	0x75, 0x6e, 0x63, 0x44, 0x61, 0x74, 0x61, 0x22, 0x12, 0x0a, 0x10, 0x53, 0x65, 0x74, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1c, 0x0a, 0x1a, 0x53,
	0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x50, 0x0a, 0x1b, 0x53, 0x75, 0x70,
	0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x14, 0x73, 0x75, 0x70, 0x70,
	0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x13, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
	0x64, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x22, 0x19, 0x0a, 0x17, 0x44,
	0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x45, 0x0a, 0x18, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c,
	0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x61, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x64, 0x65,
	0x66, 0x61, 0x75, 0x6c, 0x74, 0x41, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x22, 0x30, 0x0a,
	0x10, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x22,
	0x3b, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a, 0x0f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x44, 0x61, 0x74, 0x61, 0x22, 0x63, 0x0a, 0x12,
	0x53, 0x69, 0x67, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x33, 0x0a, 0x0c,
	0x73, 0x69, 0x67, 0x6e, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x4f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x52, 0x0b, 0x73, 0x69, 0x67, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x22, 0x33, 0x0a, 0x13, 0x53, 0x69, 0x67, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x8a, 0x01, 0x0a, 0x16, 0x56, 0x65, 0x72, 0x69, 0x66,
	0x79, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x38, 0x0a, 0x0e, 0x76, 0x65, 0x72,
	0x69, 0x66, 0x79, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x11, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x4f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x22, 0x19, 0x0a, 0x17, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x12,
	0x0a, 0x10, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x3b, 0x0a, 0x11, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a, 0x0f, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x44, 0x61, 0x74, 0x61, 0x22,
	0x15, 0x0a, 0x13, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x16, 0x0a, 0x14, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x48,
	0x0a, 0x0b, 0x53, 0x69, 0x67, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x39, 0x0a,
	0x0e, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0d, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x49, 0x0a, 0x0c, 0x56, 0x65, 0x72, 0x69,
	0x66, 0x79, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x39, 0x0a, 0x0e, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x12, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x22, 0x62, 0x0a, 0x0d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x5f, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x64, 0x69, 0x67, 0x65, 0x73,
	0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x30, 0x0a, 0x0b, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x5f,
	0x6f, 0x70, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6b, 0x6d, 0x73,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x4f, 0x70, 0x74, 0x73, 0x52, 0x0a, 0x73, 0x69, 0x67,
	0x6e, 0x65, 0x72, 0x4f, 0x70, 0x74, 0x73, 0x22, 0x32, 0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x65,
	0x72, 0x4f, 0x70, 0x74, 0x73, 0x12, 0x24, 0x0a, 0x0e, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x66, 0x75,
	0x6e, 0x63, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x68,
	0x61, 0x73, 0x68, 0x46, 0x75, 0x6e, 0x63, 0x44, 0x61, 0x74, 0x61, 0x32, 0xbd, 0x04, 0x0a, 0x0a,
	0x4b, 0x4d, 0x53, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x37, 0x0a, 0x08, 0x53, 0x65,
	0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x14, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x53, 0x65, 0x74,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x15, 0x2e, 0x6b,
	0x6d, 0x73, 0x2e, 0x53, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x58, 0x0a, 0x13, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64,
	0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x12, 0x1f, 0x2e, 0x6b, 0x6d, 0x73,
	0x2e, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69,
	0x74, 0x68, 0x6d, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e, 0x6b, 0x6d,
	0x73, 0x2e, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x41, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4f, 0x0a,
	0x10, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x12, 0x1c, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x41,
	0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1d, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x41, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3a,
	0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x15, 0x2e, 0x6b, 0x6d,
	0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x16, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x53, 0x69,
	0x67, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x17, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x53, 0x69, 0x67, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x18, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4c, 0x0a, 0x0f,
	0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12,
	0x1b, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x6b,
	0x6d, 0x73, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3a, 0x0a, 0x09, 0x50, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x15, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x50, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x0c, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x12, 0x18, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x43, 0x72, 0x79,
	0x70, 0x74, 0x6f, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x19, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x53, 0x69, 0x67,
	0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x42, 0x5a, 0x40, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x70, 0x6b, 0x67, 0x2f,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x6b, 0x6d,
	0x73, 0x67, 0x6f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_kms_proto_rawDescOnce sync.Once
	file_proto_kms_proto_rawDescData = file_proto_kms_proto_rawDesc
)

func file_proto_kms_proto_rawDescGZIP() []byte {
	file_proto_kms_proto_rawDescOnce.Do(func() {
		file_proto_kms_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_kms_proto_rawDescData)
	})
	return file_proto_kms_proto_rawDescData
}

var file_proto_kms_proto_msgTypes = make([]protoimpl.MessageInfo, 20)
var file_proto_kms_proto_goTypes = []any{
	(*SetStateRequest)(nil),             // 0: kms.SetStateRequest
	(*SetStateResponse)(nil),            // 1: kms.SetStateResponse
	(*SupportedAlgorithmsRequest)(nil),  // 2: kms.SupportedAlgorithmsRequest
	(*SupportedAlgorithmsResponse)(nil), // 3: kms.SupportedAlgorithmsResponse
	(*DefaultAlgorithmRequest)(nil),     // 4: kms.DefaultAlgorithmRequest
	(*DefaultAlgorithmResponse)(nil),    // 5: kms.DefaultAlgorithmResponse
	(*CreateKeyRequest)(nil),            // 6: kms.CreateKeyRequest
	(*CreateKeyResponse)(nil),           // 7: kms.CreateKeyResponse
	(*SignMessageRequest)(nil),          // 8: kms.SignMessageRequest
	(*SignMessageResponse)(nil),         // 9: kms.SignMessageResponse
	(*VerifySignatureRequest)(nil),      // 10: kms.VerifySignatureRequest
	(*VerifySignatureResponse)(nil),     // 11: kms.VerifySignatureResponse
	(*PublicKeyRequest)(nil),            // 12: kms.PublicKeyRequest
	(*PublicKeyResponse)(nil),           // 13: kms.PublicKeyResponse
	(*CryptoSignerRequest)(nil),         // 14: kms.CryptoSignerRequest
	(*CryptoSignerResponse)(nil),        // 15: kms.CryptoSignerResponse
	(*SignOptions)(nil),                 // 16: kms.SignOptions
	(*VerifyOption)(nil),                // 17: kms.VerifyOption
	(*MessageOption)(nil),               // 18: kms.MessageOption
	(*SignerOpts)(nil),                  // 19: kms.SignerOpts
}
var file_proto_kms_proto_depIdxs = []int32{
	16, // 0: kms.SignMessageRequest.sign_options:type_name -> kms.SignOptions
	17, // 1: kms.VerifySignatureRequest.verify_options:type_name -> kms.VerifyOption
	18, // 2: kms.SignOptions.message_option:type_name -> kms.MessageOption
	18, // 3: kms.VerifyOption.message_option:type_name -> kms.MessageOption
	19, // 4: kms.MessageOption.signer_opts:type_name -> kms.SignerOpts
	0,  // 5: kms.KMSService.SetState:input_type -> kms.SetStateRequest
	2,  // 6: kms.KMSService.SupportedAlgorithms:input_type -> kms.SupportedAlgorithmsRequest
	4,  // 7: kms.KMSService.DefaultAlgorithm:input_type -> kms.DefaultAlgorithmRequest
	6,  // 8: kms.KMSService.CreateKey:input_type -> kms.CreateKeyRequest
	8,  // 9: kms.KMSService.SignMessage:input_type -> kms.SignMessageRequest
	10, // 10: kms.KMSService.VerifySignature:input_type -> kms.VerifySignatureRequest
	12, // 11: kms.KMSService.PublicKey:input_type -> kms.PublicKeyRequest
	14, // 12: kms.KMSService.CryptoSigner:input_type -> kms.CryptoSignerRequest
	1,  // 13: kms.KMSService.SetState:output_type -> kms.SetStateResponse
	3,  // 14: kms.KMSService.SupportedAlgorithms:output_type -> kms.SupportedAlgorithmsResponse
	5,  // 15: kms.KMSService.DefaultAlgorithm:output_type -> kms.DefaultAlgorithmResponse
	7,  // 16: kms.KMSService.CreateKey:output_type -> kms.CreateKeyResponse
	9,  // 17: kms.KMSService.SignMessage:output_type -> kms.SignMessageResponse
	11, // 18: kms.KMSService.VerifySignature:output_type -> kms.VerifySignatureResponse
	13, // 19: kms.KMSService.PublicKey:output_type -> kms.PublicKeyResponse
	15, // 20: kms.KMSService.CryptoSigner:output_type -> kms.CryptoSignerResponse
	13, // [13:21] is the sub-list for method output_type
	5,  // [5:13] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_proto_kms_proto_init() }
func file_proto_kms_proto_init() {
	if File_proto_kms_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_kms_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   20,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_kms_proto_goTypes,
		DependencyIndexes: file_proto_kms_proto_depIdxs,
		MessageInfos:      file_proto_kms_proto_msgTypes,
	}.Build()
	File_proto_kms_proto = out.File
	file_proto_kms_proto_rawDesc = nil
	file_proto_kms_proto_goTypes = nil
	file_proto_kms_proto_depIdxs = nil
}
