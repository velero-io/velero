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

package framework

import (
	"os"
	"strings"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/framework/backupitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	ibav1 "github.com/vmware-tanzu/velero/pkg/plugin/framework/itemblockaction/v1"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/framework/restoreitemaction/v2"
)

// Server serves registered plugin implementations.
type Server interface {
	// BindFlags defines the plugin server's command-line flags
	// on the provided FlagSet. If you're not sure what flag set
	// to use, pflag.CommandLine is the default set of command-line
	// flags.
	//
	// This method must be called prior to calling .Serve().
	BindFlags(flags *pflag.FlagSet) Server

	// GetConfig return the config parsed from the flags
	GetConfig() *config.Config

	// RegisterBackupItemAction registers a backup item action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterBackupItemAction(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterBackupItemActions registers multiple backup item actions.
	RegisterBackupItemActions(map[string]common.HandlerInitializer) Server

	// RegisterBackupItemActionV2 registers a v2 backup item action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterBackupItemActionV2(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterBackupItemActionsV2 registers multiple v2 backup item actions.
	RegisterBackupItemActionsV2(map[string]common.HandlerInitializer) Server

	// RegisterVolumeSnapshotter registers a volume snapshotter. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterVolumeSnapshotter(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterVolumeSnapshotters registers multiple volume snapshotters.
	RegisterVolumeSnapshotters(map[string]common.HandlerInitializer) Server

	// RegisterObjectStore registers an object store. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterObjectStore(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterObjectStores registers multiple object stores.
	RegisterObjectStores(map[string]common.HandlerInitializer) Server

	// RegisterRestoreItemAction registers a restore item action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterRestoreItemAction(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterRestoreItemActions registers multiple restore item actions.
	RegisterRestoreItemActions(map[string]common.HandlerInitializer) Server

	// RegisterRestoreItemActionV2 registers a v2 restore item action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterRestoreItemActionV2(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterRestoreItemActionsV2 registers multiple v2 restore item actions.
	RegisterRestoreItemActionsV2(map[string]common.HandlerInitializer) Server

	// RegisterDeleteItemAction registers a delete item action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterDeleteItemAction(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterDeleteItemActions registers multiple Delete item actions.
	RegisterDeleteItemActions(map[string]common.HandlerInitializer) Server

	// RegisterItemBlockAction registers a ItemBlock action. Accepted format
	// for the plugin name is <DNS subdomain>/<non-empty name>.
	RegisterItemBlockAction(pluginName string, initializer common.HandlerInitializer) Server

	// RegisterItemBlockActions registers multiple ItemBlock actions.
	RegisterItemBlockActions(map[string]common.HandlerInitializer) Server

	// Server runs the plugin server.
	Serve()
}

// server implements Server.
type server struct {
	config              *config.Config
	log                 *logrus.Logger
	flagSet             *pflag.FlagSet
	backupItemAction    *BackupItemActionPlugin
	backupItemActionV2  *biav2.BackupItemActionPlugin
	volumeSnapshotter   *VolumeSnapshotterPlugin
	objectStore         *ObjectStorePlugin
	restoreItemAction   *RestoreItemActionPlugin
	restoreItemActionV2 *riav2.RestoreItemActionPlugin
	deleteItemAction    *DeleteItemActionPlugin
	itemBlockAction     *ibav1.ItemBlockActionPlugin
}

// NewServer returns a new Server
func NewServer() Server {
	log := newLogger()

	return &server{
		config:              config.GetDefaultConfig(),
		log:                 log,
		backupItemAction:    NewBackupItemActionPlugin(common.ServerLogger(log)),
		backupItemActionV2:  biav2.NewBackupItemActionPlugin(common.ServerLogger(log)),
		volumeSnapshotter:   NewVolumeSnapshotterPlugin(common.ServerLogger(log)),
		objectStore:         NewObjectStorePlugin(common.ServerLogger(log)),
		restoreItemAction:   NewRestoreItemActionPlugin(common.ServerLogger(log)),
		restoreItemActionV2: riav2.NewRestoreItemActionPlugin(common.ServerLogger(log)),
		deleteItemAction:    NewDeleteItemActionPlugin(common.ServerLogger(log)),
		itemBlockAction:     ibav1.NewItemBlockActionPlugin(common.ServerLogger(log)),
	}
}

func (s *server) BindFlags(flags *pflag.FlagSet) Server {
	s.flagSet = flags
	s.config.BindFlags(flags)
	s.flagSet.ParseErrorsAllowlist.UnknownFlags = true // Velero.io word list : ignore
	return s
}

func (s *server) GetConfig() *config.Config {
	return s.config
}

func (s *server) RegisterBackupItemAction(name string, initializer common.HandlerInitializer) Server {
	s.backupItemAction.Register(name, initializer)
	return s
}

func (s *server) RegisterBackupItemActions(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterBackupItemAction(name, m[name])
	}
	return s
}

func (s *server) RegisterBackupItemActionV2(name string, initializer common.HandlerInitializer) Server {
	s.backupItemActionV2.Register(name, initializer)
	return s
}

func (s *server) RegisterBackupItemActionsV2(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterBackupItemActionV2(name, m[name])
	}
	return s
}

func (s *server) RegisterVolumeSnapshotter(name string, initializer common.HandlerInitializer) Server {
	s.volumeSnapshotter.Register(name, initializer)
	return s
}

func (s *server) RegisterVolumeSnapshotters(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterVolumeSnapshotter(name, m[name])
	}
	return s
}

func (s *server) RegisterObjectStore(name string, initializer common.HandlerInitializer) Server {
	s.objectStore.Register(name, initializer)
	return s
}

func (s *server) RegisterObjectStores(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterObjectStore(name, m[name])
	}
	return s
}

func (s *server) RegisterRestoreItemAction(name string, initializer common.HandlerInitializer) Server {
	s.restoreItemAction.Register(name, initializer)
	return s
}

func (s *server) RegisterRestoreItemActions(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterRestoreItemAction(name, m[name])
	}
	return s
}

func (s *server) RegisterRestoreItemActionV2(name string, initializer common.HandlerInitializer) Server {
	s.restoreItemActionV2.Register(name, initializer)
	return s
}

func (s *server) RegisterRestoreItemActionsV2(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterRestoreItemActionV2(name, m[name])
	}
	return s
}

func (s *server) RegisterDeleteItemAction(name string, initializer common.HandlerInitializer) Server {
	s.deleteItemAction.Register(name, initializer)
	return s
}

func (s *server) RegisterDeleteItemActions(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterDeleteItemAction(name, m[name])
	}
	return s
}

func (s *server) RegisterItemBlockAction(name string, initializer common.HandlerInitializer) Server {
	s.itemBlockAction.Register(name, initializer)
	return s
}

func (s *server) RegisterItemBlockActions(m map[string]common.HandlerInitializer) Server {
	for name := range m {
		s.RegisterItemBlockAction(name, m[name])
	}
	return s
}

// getNames returns a list of PluginIdentifiers registered with plugin.
func getNames(command string, kind common.PluginKind, plugin Interface) []PluginIdentifier {
	var pluginIdentifiers []PluginIdentifier

	for _, name := range plugin.Names() {
		id := PluginIdentifier{Command: command, Kind: kind, Name: name}
		pluginIdentifiers = append(pluginIdentifiers, id)
	}

	return pluginIdentifiers
}

func (s *server) Serve() {
	if s.flagSet != nil && !s.flagSet.Parsed() {
		s.log.Debugf("Parsing flags")
		if err := s.flagSet.Parse(os.Args[1:]); err != nil {
			s.log.Errorf("fail to parse the flags: %s", err.Error())
			return
		}
	}

	s.log.Level = s.config.LogLevel.Parse()
	s.log.Debugf("Setting log level to %s", strings.ToUpper(s.log.Level.String()))

	command := os.Args[0]

	var pluginIdentifiers []PluginIdentifier
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindBackupItemAction, s.backupItemAction)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindBackupItemActionV2, s.backupItemActionV2)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindVolumeSnapshotter, s.volumeSnapshotter)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindObjectStore, s.objectStore)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindRestoreItemAction, s.restoreItemAction)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindRestoreItemActionV2, s.restoreItemActionV2)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindDeleteItemAction, s.deleteItemAction)...)
	pluginIdentifiers = append(pluginIdentifiers, getNames(command, common.PluginKindItemBlockAction, s.itemBlockAction)...)

	pluginLister := NewPluginLister(pluginIdentifiers...)

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake(),
		Plugins: map[string]plugin.Plugin{
			string(common.PluginKindBackupItemAction):    s.backupItemAction,
			string(common.PluginKindBackupItemActionV2):  s.backupItemActionV2,
			string(common.PluginKindVolumeSnapshotter):   s.volumeSnapshotter,
			string(common.PluginKindObjectStore):         s.objectStore,
			string(common.PluginKindPluginLister):        NewPluginListerPlugin(pluginLister),
			string(common.PluginKindRestoreItemAction):   s.restoreItemAction,
			string(common.PluginKindRestoreItemActionV2): s.restoreItemActionV2,
			string(common.PluginKindDeleteItemAction):    s.deleteItemAction,
			string(common.PluginKindItemBlockAction):     s.itemBlockAction,
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
