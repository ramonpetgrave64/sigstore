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

// Package cliplugin implements the plugin functionality.
package cliplugin

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

const (
	// PluginBinaryPrefix is the prefix for all plugin binaries. e.g., sigstore-kms-my-hsm.
	PluginBinaryPrefix = "sigstore-kms-"
)

// init registers the plugin system as a provider. It does not search for plugin programs.
// users must import this package, e.g.,  `import _ "github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"`
func init() {
	kms.AddProvider(kms.CLIPluginProviderKey, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc, opts...)
	})
}

// LoadSignerVerifier creates a PluginClient with these InitOptions.
func LoadSignerVerifier(ctx context.Context, inputKeyresourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
	parts := strings.SplitN(inputKeyresourceID, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected format: [plugin name]://[key ref], got: %s", ErrorParsingPluginName, inputKeyresourceID)
	}
	pluginName, keyResourceID := parts[0], parts[1]
	executable := PluginBinaryPrefix + pluginName
	initOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
		// TODO: include extracted values from opts
	}
	pluginClient := newPluginClient(executable, initOptions, makeCommand)
	return pluginClient, nil
}
