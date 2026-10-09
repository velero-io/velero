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

package restore

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
)

// LogsOptions holds the state for the restore logs command, mirroring
// pkg/cmd/cli/backup.LogsOptions so both commands are shaped the same way.
type LogsOptions struct {
	Timeout               time.Duration
	InsecureSkipTLSVerify bool
	CaCertFile            string
	Client                kbclient.Client
	RestoreName           string
}

func NewLogsOptions() LogsOptions {
	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}

	return LogsOptions{
		Timeout:               time.Minute,
		InsecureSkipTLSVerify: false,
		CaCertFile:            config.CACertFile(),
	}
}

func (l *LogsOptions) BindFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&l.Timeout, "timeout", l.Timeout, "How long to wait to receive logs.")
	flags.BoolVar(&l.InsecureSkipTLSVerify, "insecure-skip-tls-verify", l.InsecureSkipTLSVerify, "If true, the object store's TLS certificate will not be checked for validity. This is insecure and susceptible to man-in-the-middle attacks. Not recommended for production.")
	flags.StringVar(&l.CaCertFile, "cacert", l.CaCertFile, "Path to a certificate bundle to use when verifying TLS connections. If not specified, the CA certificate from the BackupStorageLocation will be used if available.")
}

func (l *LogsOptions) Run(c *cobra.Command, f client.Factory) error {
	restore := new(velerov1api.Restore)
	err := l.Client.Get(context.Background(), kbclient.ObjectKey{Namespace: f.Namespace(), Name: l.RestoreName}, restore)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("restore %q does not exist", l.RestoreName)
	} else if err != nil {
		return fmt.Errorf("error checking for restore %q: %v", l.RestoreName, err)
	}

	switch restore.Status.Phase {
	case velerov1api.RestorePhaseCompleted, velerov1api.RestorePhaseFailed, velerov1api.RestorePhasePartiallyFailed, velerov1api.RestorePhaseWaitingForPluginOperations, velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed:
		// terminal and waiting for plugin operations phases, do nothing.
	default:
		return fmt.Errorf("logs for restore %q are not available until it's finished processing, please wait "+
			"until the restore has a phase of Completed or Failed and try again", l.RestoreName)
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromRestore(context.Background(), l.Client, f.Namespace(), restore)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		fmt.Fprintf(os.Stderr, "WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	return downloadrequest.StreamWithBSLCACert(context.Background(), l.Client, f.Namespace(), l.RestoreName, velerov1api.DownloadTargetKindRestoreLog, os.Stdout, l.Timeout, l.InsecureSkipTLSVerify, l.CaCertFile, bslCACert)
}

func (l *LogsOptions) Complete(args []string, f client.Factory) error {
	if len(args) > 0 {
		l.RestoreName = args[0]
	}

	kbClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}
	l.Client = kbClient
	return nil
}

func NewLogsCommand(f client.Factory) *cobra.Command {
	l := NewLogsOptions()

	c := &cobra.Command{
		Use:   "logs RESTORE",
		Short: "Get restore logs",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			err := l.Complete(args, f)
			cmd.CheckError(err)

			err = l.Run(c, f)
			cmd.CheckError(err)
		},
	}

	c.ValidArgsFunction = cli.CompleteRestoreNames(f)
	l.BindFlags(c.Flags())

	return c
}
