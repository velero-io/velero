/*
Copyright 2020 the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package clientmgmt contains the plugin client for Velero.
package process

import (
	"context"
	"os"
	"os/exec"

	hclog "github.com/hashicorp/go-hclog"
	hcplugin "github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"

	"github.com/velero-io/velero/pkg/plugin/framework"
	biav2 "github.com/velero-io/velero/pkg/plugin/framework/backupitemaction/v2"
	"github.com/velero-io/velero/pkg/plugin/framework/common"
	ibav1 "github.com/velero-io/velero/pkg/plugin/framework/itemblockaction/v1"
	riav2 "github.com/velero-io/velero/pkg/plugin/framework/restoreitemaction/v2"
)

// clientBuilder builds go-plugin Clients.
type clientBuilder struct {
	commandName  string
	commandArgs  []string
	clientLogger logrus.FieldLogger
	pluginLogger hclog.Logger
}

// newClientBuilder returns a new clientBuilder with commandName to name. If the command matches the currently running
// process (i.e. velero), this also sets commandArgs to the internal Velero command to run plugins.
func newClientBuilder(command string, logger logrus.FieldLogger, logLevel logrus.Level) *clientBuilder {
	b := &clientBuilder{
		commandName:  command,
		clientLogger: logger,
		pluginLogger: newLogrusAdapter(logger, logLevel),
	}
	if command == os.Args[0] {
		// For plugins compiled into the velero executable, we need to run "velero run-plugins"
		b.commandArgs = []string{"run-plugins"}
	}
	// exclude "velero" and "server" from "velero server --flags ..."
	b.commandArgs = append(b.commandArgs, os.Args[2:]...)

	return b
}

func newLogrusAdapter(pluginLogger logrus.FieldLogger, logLevel logrus.Level) *logrusAdapter {
	return &logrusAdapter{impl: pluginLogger, level: logLevel}
}

func (b *clientBuilder) clientConfig() *hcplugin.ClientConfig {
	return &hcplugin.ClientConfig{
		HandshakeConfig:  framework.Handshake(),
		AllowedProtocols: []hcplugin.Protocol{hcplugin.ProtocolGRPC},
		Plugins: map[string]hcplugin.Plugin{
			string(common.PluginKindBackupItemAction):    framework.NewBackupItemActionPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindBackupItemActionV2):  biav2.NewBackupItemActionPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindVolumeSnapshotter):   framework.NewVolumeSnapshotterPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindObjectStore):         framework.NewObjectStorePlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindPluginLister):        &framework.PluginListerPlugin{},
			string(common.PluginKindRestoreItemAction):   framework.NewRestoreItemActionPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindRestoreItemActionV2): riav2.NewRestoreItemActionPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindDeleteItemAction):    framework.NewDeleteItemActionPlugin(common.ClientLogger(b.clientLogger)),
			string(common.PluginKindItemBlockAction):     ibav1.NewItemBlockActionPlugin(common.ClientLogger(b.clientLogger)),
		},
		Logger: b.pluginLogger,
		Cmd:    exec.CommandContext(context.Background(), b.commandName, b.commandArgs...), //nolint:gosec // Internal call. No need to check the command line.
	}
}

// client creates a new go-plugin Client with support for all of Velero's plugin kinds (BackupItemAction, VolumeSnapshotter,
// ObjectStore, PluginLister, RestoreItemAction).
func (b *clientBuilder) client() *hcplugin.Client {
	return hcplugin.NewClient(b.clientConfig())
}
