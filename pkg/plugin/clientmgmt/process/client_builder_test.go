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

package process

import (
	"os"
	"os/exec"
	"testing"

	hcplugin "github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/pkg/plugin/framework"
	biav2 "github.com/velero-io/velero/pkg/plugin/framework/backupitemaction/v2"
	"github.com/velero-io/velero/pkg/plugin/framework/common"
	ibav1 "github.com/velero-io/velero/pkg/plugin/framework/itemblockaction/v1"
	riav2 "github.com/velero-io/velero/pkg/plugin/framework/restoreitemaction/v2"
	"github.com/velero-io/velero/pkg/test"
)

func TestNewClientBuilder(t *testing.T) {
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel
	cb := newClientBuilder("velero", logger, logLevel)
	assert.Equal(t, "velero", cb.commandName)
	assert.Equal(t, newLogrusAdapter(logger, logLevel), cb.pluginLogger)

	cb = newClientBuilder(os.Args[0], logger, logLevel)
	assert.Equal(t, cb.commandName, os.Args[0])
	assert.Equal(t, newLogrusAdapter(logger, logLevel), cb.pluginLogger)
}

func TestClientConfig(t *testing.T) {
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel
	cb := newClientBuilder("velero", logger, logLevel)

	expected := &hcplugin.ClientConfig{
		HandshakeConfig:  framework.Handshake(),
		AllowedProtocols: []hcplugin.Protocol{hcplugin.ProtocolGRPC},
		Plugins: map[string]hcplugin.Plugin{
			string(common.PluginKindBackupItemAction):    framework.NewBackupItemActionPlugin(common.ClientLogger(logger)),
			string(common.PluginKindBackupItemActionV2):  biav2.NewBackupItemActionPlugin(common.ClientLogger(logger)),
			string(common.PluginKindVolumeSnapshotter):   framework.NewVolumeSnapshotterPlugin(common.ClientLogger(logger)),
			string(common.PluginKindObjectStore):         framework.NewObjectStorePlugin(common.ClientLogger(logger)),
			string(common.PluginKindPluginLister):        &framework.PluginListerPlugin{},
			string(common.PluginKindRestoreItemAction):   framework.NewRestoreItemActionPlugin(common.ClientLogger(logger)),
			string(common.PluginKindRestoreItemActionV2): riav2.NewRestoreItemActionPlugin(common.ClientLogger(logger)),
			string(common.PluginKindDeleteItemAction):    framework.NewDeleteItemActionPlugin(common.ClientLogger(logger)),
			string(common.PluginKindItemBlockAction):     ibav1.NewItemBlockActionPlugin(common.ClientLogger(logger)),
		},
		Logger: cb.pluginLogger,
		Cmd:    exec.CommandContext(t.Context(), cb.commandName, cb.commandArgs...),
	}

	cc := cb.clientConfig()
	assert.Equal(t, expected.HandshakeConfig, cc.HandshakeConfig)
	assert.Equal(t, expected.AllowedProtocols, cc.AllowedProtocols)
	assert.Equal(t, expected.Plugins, cc.Plugins)
}
