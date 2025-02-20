package cliplugin

import (
	"bufio"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/encoding"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/internal/signerverifier"
)

func LoadSignerVerifier2(ctx context.Context, inputKeyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (signerverifier.SignerVerifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	executable, keyResourceID, err := getPluginExecutableAndKeyResourceID(inputKeyResourceID)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath(executable); err != nil {
		return nil, err
	}
	initOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
		RPCOptions:      encoding.PackRPCOptions(opts),
	}
	if deadline, ok := ctx.Deadline(); ok {
		initOptions.CtxDeadline = &deadline
	}
	return newPluginClient2(ctx, executable, initOptions)
}

type PluginClient2 struct {
	signerverifier.SignerVerifier
	stdinWriter  io.WriteCloser
	stdoutReader *bufio.Reader
}

func newPluginClient2(ctx context.Context, executable string, initOptions *common.InitOptions) (*PluginClient2, error) {
	initOptionsEnc, err := json.Marshal(&common.PluginArgs{
		InitOptions: initOptions,
	})
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, common.ProtocolVersion, string(initOptionsEnc))
	cmd.Stderr = os.Stderr
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdoutReader := bufio.NewReader(stdoutPipe)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pluginClient := &PluginClient2{
		stdinWriter:  stdinPipe,
		stdoutReader: stdoutReader,
	}
	return pluginClient, nil
}

// invokePlugin sends the method args and waits for a response.
func (c PluginClient2) invokePlugin(pluginArgs *common.PluginArgs) (*common.PluginResp, error) {
	slog.Info("invokePlugin", "beforewrite", true)
	argsEnc, err := json.Marshal(pluginArgs)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(c.stdinWriter, string(argsEnc)); err != nil {
		return nil, err
	}
	slog.Info("invokePlugin", "afterwrite", true)
	respEnc, err := c.stdoutReader.ReadBytes(byte('\n'))
	slog.Info("invokePlugin", "resp", string(respEnc))
	if err != nil {
		return nil, err
	}
	var pluginResp common.PluginResp
	if err := json.Unmarshal(respEnc, &pluginResp); err != nil {
		return nil, err
	}
	return &pluginResp, nil
}

// DefaultAlgorithm calls and returns the plugin's implementation of DefaultAlgorithm().
func (c PluginClient2) DefaultAlgorithm() string {
	args := &common.PluginArgs{
		MethodArgs: &common.MethodArgs{
			MethodName:       common.DefaultAlgorithmMethodName,
			DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
		},
	}
	resp, err := c.invokePlugin(args)
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("DefaultAlgorithm", "resp", resp)
	return resp.DefaultAlgorithm.DefaultAlgorithm
}
