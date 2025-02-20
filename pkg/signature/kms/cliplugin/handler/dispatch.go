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

// Package handler implements helper functions for plugins written in go. It will extract
// values from PluginArgs and pass them the real SignerVerifier implementation, and then package
// responses into PluginResp.
package handler

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/internal/signerverifier"
)

var (
	// ErrorPluginArgsParse indicates a problem parsing the plugin args
	ErrorPluginArgsParse = errors.New("error parsing plugin args")
	// ErrorUnsupportedMethod indicates that an unsupported method name was supplied.
	ErrorUnsupportedMethod = errors.New("unsupported method")
)

// GetPluginArgs parses the PluginArgs from the os args.
func GetPluginArgs(osArgs []string) (*common.PluginArgs, error) {
	if len(osArgs) < 3 {
		return nil, fmt.Errorf("%w: expected at least 3 args, got %d", ErrorPluginArgsParse, len(osArgs))
	}
	argsStr := osArgs[2]
	var args common.PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

// WriteResponse writes JSON-serialized PluginResp to the output.
func WriteResponse(stdout io.Writer, resp *common.PluginResp) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(enc))
	return nil
}

// WriteErrorResponse writes a response with only an error message to the output.
func WriteErrorResponse(stdout io.Writer, err error) error {
	resp := &common.PluginResp{
		ErrorMessage: err.Error(),
	}
	return WriteResponse(stdout, resp)
}

// Dispatch routes to handler functions based on the PluginArgs.
// If there is an error to be returned, it will also call WriteResponse with the error.
func Dispatch(stdout io.Writer, stdin io.Reader, pluginArgs *common.PluginArgs, impl signerverifier.SignerVerifier) (*common.PluginResp, error) {
	var resp common.PluginResp
	var err error
	switch pluginArgs.MethodName {
	case common.DefaultAlgorithmMethodName:
		resp.DefaultAlgorithm, err = DefaultAlgorithm(stdin, pluginArgs.DefaultAlgorithm, impl)
	case common.SupportedAlgorithmsMethodName:
		resp.SupportedAlgorithms, err = SupportedAlgorithms(stdin, pluginArgs.SupportedAlgorithms, impl)
	case common.CreateKeyMethodName:
		resp.CreateKey, err = CreateKey(stdin, pluginArgs.CreateKey, impl)
	case common.PublicKeyMethodName:
		resp.PublicKey, err = PublicKey(stdin, pluginArgs.PublicKey, impl)
	case common.SignMessageMethodName:
		resp.SignMessage, err = SignMessage(stdin, pluginArgs.SignMessage, impl)
	case common.VerifySignatureMethodName:
		resp.VerifySignature, err = VerifySignature(stdin, pluginArgs.VerifySignature, impl)
	default:
		err = fmt.Errorf("%w: %s", ErrorUnsupportedMethod, pluginArgs.MethodName)
	}
	if err != nil {
		resp.ErrorMessage = err.Error()
	}
	err = WriteResponse(stdout, &resp)
	return &resp, err
}

func LoopDispatch(stdout io.Writer, stdin io.Reader, impl signerverifier.SignerVerifier) error {
	slog.Info("LoopDispatch")
	// reader := bufio.NewReader(stdin)
	// for {
	// 	slog.Info("LoopDispatch", "for", true)
	// 	line, err := reader.ReadBytes('\n')
	// 	slog.Info("LoopDispatch", "line", line)
	// 	if err != nil && err != io.EOF {
	// 		slog.Error("LoopDispatch", "readErr", err)
	// 		return err
	// 	}
	// 	var pluginArgs common.PluginArgs
	// 	if err := json.Unmarshal(line, &pluginArgs); err != nil {
	// 		slog.Error("LoopDispatch", "unmarshalErr", err)
	// 		return err
	// 	}
	// 	slog.Info("LoopDispatch", "args", pluginArgs)
	// 	pluginResp, err := Dispatch(stdout, stdin, &pluginArgs, impl)
	// 	if err != nil {
	// 		slog.Error("LoopDispatch", "dispatchErr", err)
	// 		return err
	// 	}
	// 	slog.Info("LoopDispatch", "pluginResp", pluginResp)
	// }
	scanner := bufio.NewScanner(stdin)
	slog.Info("LoopDispatch", "scanner", scanner)
	for scanner.Scan() {
		slog.Info("LoopDispatch", "scanner.Scan", true)
		line := scanner.Bytes()
		slog.Info("LoopDispatch", "line", string(line))
		var pluginArgs common.PluginArgs
		if err := json.Unmarshal(line, &pluginArgs); err != nil {
			return err
		}
		slog.Info("LoopDispatch", "args", pluginArgs)
		if _, err := Dispatch(stdout, stdin, &pluginArgs, impl); err != nil {
			slog.Error("LoopDispatch", "dispatchErr", err)
			return err
		}
	}
	return nil
}
