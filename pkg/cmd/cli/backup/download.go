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
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
)

func NewDownloadCommand(f client.Factory) *cobra.Command {
	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}
	o := NewDownloadOptions()
	o.caCertFile = config.CACertFile()

	c := &cobra.Command{
		Use:   "download NAME",
		Short: "Download all Kubernetes manifests for a backup",
		Long:  "Download all Kubernetes manifests for a backup. Contents of persistent volume snapshots are not included.",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args))
			cmd.CheckError(o.Validate(c, args, f))
			cmd.CheckError(o.Run(c, f))
		},
	}

	o.BindFlags(c.Flags())

	return c
}

type DownloadOptions struct {
	Name                  string
	Output                string
	Force                 bool
	Timeout               time.Duration
	InsecureSkipTLSVerify bool
	writeOptions          int
	caCertFile            string
}

func NewDownloadOptions() *DownloadOptions {
	return &DownloadOptions{
		Timeout: time.Minute,
	}
}

func (o *DownloadOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", o.Output, "Path to output file. Defaults to <NAME>-data.tar.gz in the current directory.")
	flags.BoolVar(&o.Force, "force", o.Force, "Forces the download and will overwrite file if it exists already.")
	flags.DurationVar(&o.Timeout, "timeout", o.Timeout, "Maximum time to wait to process download request.")
	flags.BoolVar(&o.InsecureSkipTLSVerify, "insecure-skip-tls-verify", o.InsecureSkipTLSVerify, "If true, the object store's TLS certificate will not be checked for validity. This is insecure and susceptible to man-in-the-middle attacks. Not recommended for production.")
	flags.StringVar(&o.caCertFile, "cacert", o.caCertFile, "Path to a certificate bundle to use when verifying TLS connections. If not specified, the CA certificate from the BackupStorageLocation will be used if available.")
}

func (o *DownloadOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	kbClient, err := f.KubebuilderClient()
	cmd.CheckError(err)

	backup := new(velerov1api.Backup)
	if err := kbClient.Get(context.Background(), controllerclient.ObjectKey{Namespace: f.Namespace(), Name: o.Name}, backup); err != nil {
		return err
	}

	return nil
}

func (o *DownloadOptions) Complete(args []string) error {
	o.Name = args[0]

	o.writeOptions = os.O_RDWR | os.O_CREATE | os.O_EXCL
	if o.Force {
		o.writeOptions = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	}

	if o.Output == "" {
		path, err := os.Getwd()
		if err != nil {
			return errors.Wrapf(err, "error getting current directory")
		}
		o.Output = filepath.Join(path, fmt.Sprintf("%s-data.tar.gz", o.Name))
	}

	return nil
}

func (o *DownloadOptions) Run(c *cobra.Command, f client.Factory) error {
	kbClient, err := f.KubebuilderClient()
	cmd.CheckError(err)

	// Get the backup to fetch BSL cacert
	backup := new(velerov1api.Backup)
	if err := kbClient.Get(context.Background(), controllerclient.ObjectKey{Namespace: f.Namespace(), Name: o.Name}, backup); err != nil {
		return err
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(context.Background(), kbClient, f.Namespace(), backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		fmt.Fprintf(os.Stderr, "WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	// Inherit insecureSkipTLSVerify from BSL config if not set via CLI flag
	bslInsecure, err := cacert.GetInsecureSkipTLSVerifyFromBackup(context.Background(), kbClient, f.Namespace(), backup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error getting insecureSkipTLSVerify from BSL: %v\n", err)
	}

	backupDest, err := os.OpenFile(o.Output, o.writeOptions, 0600)
	if err != nil {
		return err
	}
	defer backupDest.Close()

	err = downloadrequest.StreamWithBSLCACert(context.Background(), kbClient, f.Namespace(), o.Name, velerov1api.DownloadTargetKindBackupContents, backupDest, o.Timeout, o.InsecureSkipTLSVerify || bslInsecure, o.caCertFile, bslCACert)
	if err != nil {
		os.Remove(o.Output)
		cmd.CheckError(err)
	}

	fmt.Printf("Backup %s has been successfully downloaded to %s\n", o.Name, backupDest.Name())
	return nil
}
