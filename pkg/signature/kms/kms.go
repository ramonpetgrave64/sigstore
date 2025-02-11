//
// Copyright 2021 The Sigstore Authors.
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

// Package kms implements the interface to access various ksm services
package kms

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
)

// ProviderNotFoundError indicates that no matching KMS provider was found
//
// Deprecated: ProviderNotFoundError is no longer returned by Get(). If no matching provider is found
// Get(), attempts to find a plugin program on the system, returning exec.ErrNotFound if not found.
type ProviderNotFoundError struct {
	ref string
}

func (e *ProviderNotFoundError) Error() string {
	return fmt.Sprintf("no kms provider found for key reference: %s", e.ref)
}

// ProviderInit is a function that initializes provider-specific SignerVerifier.
//
// It takes a provider-specific resource ID and hash function, and returns a
// SignerVerifier using that resource, or any error that was encountered.
type ProviderInit func(context.Context, string, crypto.Hash, ...signature.RPCOption) (SignerVerifier, error)

// AddProvider adds the provider implementation into the local cache
func AddProvider(keyResourceID string, init ProviderInit) {
	providersMap[keyResourceID] = init
}

var providersMap = map[string]ProviderInit{}

// Get returns a KMS SignerVerifier for the given resource string and hash function.
// If no matching built-in provider is found, it will try to use the plugin system as a provider.
// If keyResourceID doesn't match any of our hard-coded providers' schemas, or the plugin program
// can't be found, then it returns ProviderNotFoundError.
// It also returns an error if initializing the SignerVerifier fails.
func Get(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (SignerVerifier, error) {
	for ref, pi := range providersMap {
		if strings.HasPrefix(keyResourceID, ref) {
			sv, err := pi(ctx, keyResourceID, hashFunc, opts...)
			if err != nil {
				return nil, err
			}
			return sv, nil
		}
	}
	// We don't return a ProviderNotFoundError because cosign currently interprets those in a confusing way:
	// "error during command execution: signing ../blob.txt: reading key: loading URL: unrecognized scheme: mykms://".
	// Instead, without the ProviderNotFoundError, we would get:
	// "error during command execution: signing ../blob.txt: reading key: kms get: exec: "sigstore-kms-mykms": executable file not found in $PATH"
	// sv, err := cliplugin.LoadSignerVerifier(ctx, keyResourceID, hashFunc, opts...)
	// if errors.Is(err, exec.ErrNotFound) {
	// 	return nil, &ProviderNotFoundError{ref: keyResourceID}
	// }
	return cliplugin.LoadSignerVerifier(ctx, keyResourceID, hashFunc, opts...)
}

// SupportedProviders returns list of initialized providers
func SupportedProviders() []string {
	keys := make([]string, 0, len(providersMap))
	for key := range providersMap {
		keys = append(keys, key)
	}
	return keys
}

// SignerVerifier creates and verifies digital signatures over a message using a KMS service
type SignerVerifier interface {
	signature.SignerVerifier
	CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error)
	CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error)
	SupportedAlgorithms() []string
	DefaultAlgorithm() string
}
