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

package backup

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
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
)

type LogsOptions struct {
	Timeout               time.Duration
	InsecureSkipTLSVerify bool
	CaCertFile            string
	Client                kbclient.Client
	BackupName            string
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
	flags.StringVar(&l.CaCertFile, "cacert", l.CaCertFile, "Path to a certificate bundle to use when verifying TLS connections.")
}

func (l *LogsOptions) Run(c *cobra.Command, f client.Factory) error {
	backup := new(velerov1api.Backup)
	err := l.Client.Get(context.Background(), kbclient.ObjectKey{Namespace: f.Namespace(), Name: l.BackupName}, backup)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("backup %q does not exist", l.BackupName)
	} else if err != nil {
		return fmt.Errorf("error checking for backup %q: %v", l.BackupName, err)
	}

	switch backup.Status.Phase {
	case velerov1api.BackupPhaseCompleted, velerov1api.BackupPhasePartiallyFailed, velerov1api.BackupPhaseFailed, velerov1api.BackupPhaseWaitingForPluginOperations, velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed:
		// terminal and waiting for plugin operations phases, do nothing.
	default:
		return fmt.Errorf("logs for backup %q are not available until it's finished processing, please wait "+
			"until the backup has a phase of Completed or Failed and try again", l.BackupName)
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(context.Background(), l.Client, f.Namespace(), backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		fmt.Fprintf(os.Stderr, "WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	// Inherit insecureSkipTLSVerify from BSL config if not set via CLI flag
	bslInsecure, err := cacert.GetInsecureSkipTLSVerifyFromBackup(context.Background(), l.Client, f.Namespace(), backup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error getting insecureSkipTLSVerify from BSL: %v\n", err)
	}

	err = downloadrequest.StreamWithBSLCACert(context.Background(), l.Client, f.Namespace(), l.BackupName, velerov1api.DownloadTargetKindBackupLog, os.Stdout, l.Timeout, l.InsecureSkipTLSVerify || bslInsecure, l.CaCertFile, bslCACert)
	return err
}

func (l *LogsOptions) Complete(args []string, f client.Factory) error {
	if len(args) > 0 {
		l.BackupName = args[0]
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
		Use:   "logs BACKUP",
		Short: "Get backup logs",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			err := l.Complete(args, f)
			cmd.CheckError(err)

			err = l.Run(c, f)
			cmd.CheckError(err)
		},
	}

	l.BindFlags(c.Flags())

	return c
}
