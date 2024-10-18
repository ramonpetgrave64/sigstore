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

// Package fake implements fake signer to be used in tests
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	defaultAlgorithm = "rsa-2048"
)

// LocalSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID.
type LocalSignerVerifier struct {
	// common.KMSGoPluginSignerVerifier
	state *common.KMSGoPluginState
}

func (i LocalSignerVerifier) getKeyPath() string {
	return strings.TrimPrefix(i.state.KeyResourceID, common.ReferenceScheme)
}

func (i *LocalSignerVerifier) SetState(state *common.KMSGoPluginState) {
	i.state = state
}

// DefaultAlgorithm returns the default algorithm for the signer
func (i LocalSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

// SupportedAlgorithms returns a list with the default algorithm
func (i *LocalSignerVerifier) SupportedAlgorithms() (result []string) {
	return []string{defaultAlgorithm}
}

// CreateKey returns a new public key, and saves the private key to the KeyResourceID.
func (i LocalSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if !slices.Contains(i.SupportedAlgorithms(), algorithm) {
		return nil, fmt.Errorf("algorithm %s not supported", algorithm)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	path := i.getKeyPath()
	privateKeyFile, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("error creating private key file: %w", err)
	}
	defer privateKeyFile.Close()

	// os.WriteFile(path, privateKeyBytes, 0600)

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	return publicKey, nil
}

// loadRSAPrivateKey loads the private key from the path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// loadRSAPrivateKey returns the public key from the path.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	privateKey, err := loadRSAPrivateKey(path)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey
	return &publicKey, nil
}

// PublicKey reads the private key from the KeyResourceID and returns the public key.
func (i LocalSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	publickKey, err := loadPublicKey(i.getKeyPath())
	if err != nil {
		return nil, err
	}
	return publickKey, nil
}

func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func signMessageWithPrivateKey(privateKey *rsa.PrivateKey, message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var signerOpts crypto.SignerOpts = common.GetHashFuncFromEnv()
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	var hashFunc crypto.Hash
	if len(digest) > 0 {
		hashFunc = crypto.Hash(0)
	} else if signerOpts != nil {
		hashFunc = signerOpts.HashFunc()
		var err error
		digest, err = computeDigest(&message, hashFunc)
		if err != nil {
			return nil, err
		}
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("Error signing data:", err)
	}
	return signature, nil
}

// SignMessage signs the message with the KeyResourceID.
func (g LocalSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	privateKey, err := loadRSAPrivateKey(g.getKeyPath())
	if err != nil {
		return nil, err
	}
	return signMessageWithPrivateKey(privateKey, message, opts...)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the LocalSignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (i *LocalSignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	publicKey, err := loadPublicKey(i.getKeyPath())
	if err != nil {
		return err
	}
	var digest []byte
	var signerOpts crypto.SignerOpts = common.GetHashFuncFromEnv()

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	var hashFunc crypto.Hash
	if len(digest) > 0 {
		hashFunc = crypto.Hash(0)
	} else if signerOpts != nil {
		hashFunc = signerOpts.HashFunc()
		digest, err = computeDigest(&message, hashFunc)
		if err != nil {
			return err
		}
	}

	signatureBytes, err := io.ReadAll(signature)
	if err != nil {
		return nil
	}

	if err := rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, signatureBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

type CryptoSignerWrapper struct {
	crypto.Signer
	// Ctx            context.Context
	HashFunc       crypto.Hash
	SignerVerifier *LocalSignerVerifier
	ErrFunc        func(error)
	KeyResourceID  string
}

// CryptoSigner returns a crypto.Signer object that uses the underlying LocalSignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (i LocalSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	signer := &CryptoSignerWrapper{
		// Ctx:            ctx,
		HashFunc:       common.GetHashFuncFromEnv(),
		SignerVerifier: &i,
		ErrFunc:        errFunc,
		KeyResourceID:  i.state.KeyResourceID,
	}
	opts := common.GetHashFuncFromEnv()
	return signer, opts, nil
}

func (c CryptoSignerWrapper) Public() crypto.PublicKey {
	publicKey, err := loadPublicKey(c.KeyResourceID)
	if err != nil {
		c.ErrFunc(err)
		return nil
	}
	return publicKey
}

// Sign signs the digest and returns a signature. The rand argument is ignored.
func (c CryptoSignerWrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	privateKey, err := loadRSAPrivateKey(common.GetKeyResourceIDFromEnv())
	if err != nil {
		return nil, err
	}
	emptyMessage := strings.NewReader("")
	hashFunc := c.HashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	signOpts := []signature.SignOption{
		options.WithContext(context.Background()),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}
	return signMessageWithPrivateKey(privateKey, emptyMessage, signOpts...)
}
