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

// Package common has common code between sigstore and your plugin.
// using the github.com/hashicorp/go-plugin framework.
package common

import "errors"

var (
	ErrorUnreturnableKMSGRPC = errors.New("unreturnable error from KMS Plugin RPC/GRPC")
	ErrorNotImplemented      = errors.New("this function is not implemented")
)