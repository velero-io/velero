/*
Copyright the Velero contributors.

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

// Package backupstoreserver implements the hidden `velero backup-store-server`
// command, which runs inside a per-BackupStorageLocation worker pod. It loads the
// object-store provider plugin from the pod's plugin directory and serves it over a
// network mTLS gRPC endpoint so the central Velero process can drive it under the
// worker pod's identity.
package backupstoreserver

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vmware-tanzu/velero/pkg/bslworker"
	velerocli "github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

// Options holds the flags for the backup-store-server command.
type Options struct {
	// Provider is the object-store provider whose plugin to serve (e.g. "velero.io/azure").
	Provider string
	// ListenAddress is the host:port the gRPC server binds to.
	ListenAddress string
	// PluginDir is the directory containing the provider plugin binaries.
	PluginDir string
	// TLS materials for the mutual-TLS endpoint.
	TLSCertFile   string
	TLSKeyFile    string
	TLSCACertFile string

	LogLevelFlag *logging.LevelFlag
	FormatFlag   *logging.FormatFlag
}

// BindFlags registers the command's flags.
func (o *Options) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.Provider, "provider", o.Provider, "Name of the object store provider plugin to serve")
	flags.StringVar(&o.ListenAddress, "listen", o.ListenAddress, "host:port for the gRPC server to listen on")
	flags.StringVar(&o.PluginDir, "plugin-dir", o.PluginDir, "Directory containing Velero plugins")
	flags.StringVar(&o.TLSCertFile, "tls-cert-file", o.TLSCertFile, "Path to the PEM server certificate for mutual TLS")
	flags.StringVar(&o.TLSKeyFile, "tls-key-file", o.TLSKeyFile, "Path to the PEM server private key for mutual TLS")
	flags.StringVar(&o.TLSCACertFile, "tls-ca-cert-file", o.TLSCACertFile, "Path to the PEM CA certificate used to verify the central Velero client")
	flags.Var(o.LogLevelFlag, "log-level", fmt.Sprintf("The level at which to log. Valid values are %s.", strings.Join(o.LogLevelFlag.AllowedValues(), ", ")))
	flags.Var(o.FormatFlag, "log-format", fmt.Sprintf("The format for log output. Valid values are %s.", strings.Join(o.FormatFlag.AllowedValues(), ", ")))
}

// NewCommand returns the hidden `velero backup-store-server` command.
func NewCommand(f velerocli.Factory) *cobra.Command {
	o := &Options{
		ListenAddress: fmt.Sprintf("0.0.0.0:%d", bslworker.WorkerGRPCPort),
		PluginDir:     "/plugins",
		LogLevelFlag:  logging.LogLevelFlag(logrus.InfoLevel),
		FormatFlag:    logging.NewFormatFlag(),
	}
	c := &cobra.Command{
		Use:    "backup-store-server",
		Hidden: true,
		Short:  "VELERO INTERNAL COMMAND ONLY - not intended to be run directly by users",
		Long: "backup-store-server runs a per-BackupStorageLocation object store worker: " +
			"it serves the provider's object store plugin over a network mTLS gRPC endpoint " +
			"so that the central Velero process can drive it under this pod's identity.",
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Run(f))
		},
	}

	o.BindFlags(c.Flags())
	return c
}

// Run loads the provider plugin and serves it until the process receives a
// termination signal.
func (o *Options) Run(_ velerocli.Factory) error {
	logger := logging.DefaultLogger(o.LogLevelFlag.Parse(), o.FormatFlag.Parse())
	logger.SetOutput(os.Stdout)

	if o.Provider == "" {
		return fmt.Errorf("--provider must be specified")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Discover and load the provider's object store plugin from the pod's plugin dir.
	registry := process.NewRegistry(o.PluginDir, logger, logger.Level)
	if err := registry.DiscoverPlugins(); err != nil {
		return fmt.Errorf("discovering plugins in %q: %w", o.PluginDir, err)
	}

	pluginManager := clientmgmt.NewManager(logger, logger.Level, registry)
	defer pluginManager.CleanupClients()

	objectStore, err := pluginManager.GetObjectStore(o.Provider)
	if err != nil {
		return fmt.Errorf("getting object store for provider %q: %w", o.Provider, err)
	}

	tlsConfig, err := bslworker.LoadServerTLSConfig(o.TLSCertFile, o.TLSKeyFile, o.TLSCACertFile)
	if err != nil {
		return fmt.Errorf("loading server TLS config: %w", err)
	}

	server := bslworker.NewServer(logger, objectStore, tlsConfig)
	logger.WithFields(logrus.Fields{
		"provider": o.Provider,
		"listen":   o.ListenAddress,
	}).Info("Starting BSL worker object store server")

	return server.Serve(ctx, o.ListenAddress)
}
