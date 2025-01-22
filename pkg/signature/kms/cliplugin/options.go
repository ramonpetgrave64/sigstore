//
// Copyright 2024 The Sigstore Authors.
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

// Package cliplugin implements the plugin functionality.
package cliplugin

import (
	"context"
	"crypto"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

// getRPCOptionsAndApplyContext extracts properties of all of opts into struct ready for serializing.
// ctx will be overwritten with `signature.RPCOption.ApplyContext()` if there is a Context within the opts.
func getRPCOptionsAndApplyContext(ctx *context.Context, opts []signature.RPCOption) *common.RPCOptions {
	var keyVersion string
	var remoteVerification bool
	for _, opt := range opts {
		opt.ApplyContext(ctx)
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyRemoteVerification(&remoteVerification)
	}
	var ctxDeadline *time.Time
	if ctx != nil {
		if deadline, ok := (*ctx).Deadline(); ok {
			ctxDeadline = &deadline
		}
	}
	return &common.RPCOptions{
		CtxDeadline:        ctxDeadline,
		KeyVersion:         &keyVersion,
		RemoteVerification: &remoteVerification,
	}
}

// getMessageOptions extracts properties of all of opts into struct ready for serializing.
func getMessageOptions(opts []signature.MessageOption) *common.MessageOptions {
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	var hashFunc *crypto.Hash
	if signerOpts != nil {
		hf := signerOpts.HashFunc()
		hashFunc = &hf
	}
	return &common.MessageOptions{
		Digest:   &digest,
		HashFunc: hashFunc,
	}
}

// getMessageOptions extracts properties of all of opts into struct ready for serializing,
// ctx will be overwritten with `signature.RPCOption.ApplyContext()` if there is a Context within the opts.
func getSignOptionsAndApplyContext(ctx *context.Context, opts []signature.SignOption) *common.SignOptions {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	messageOpts := []signature.MessageOption{}
	for _, opt := range opts {
		messageOpts = append(messageOpts, opt)
	}
	return &common.SignOptions{
		RPCOptions:     getRPCOptionsAndApplyContext(ctx, rpcOpts),
		MessageOptions: getMessageOptions(messageOpts),
	}
}
