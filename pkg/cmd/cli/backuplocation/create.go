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

package backuplocation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
)

func NewCreateCommand(f client.Factory, use string) *cobra.Command {
	o := NewCreateOptions()

	c := &cobra.Command{
		Use:   use + " NAME",
		Short: "Create a backup storage location",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args, f))
			cmd.CheckError(o.Validate(c, args, f))
			cmd.CheckError(o.Run(c, f))
		},
	}

	o.BindFlags(c.Flags())
	output.BindFlags(c.Flags())
	output.ClearOutputFlagDefault(c)

	return c
}

type CreateOptions struct {
	Name                                  string
	Provider                              string
	Bucket                                string
	Credential                            flag.Map
	DefaultBackupStorageLocation          bool
	Prefix                                string
	BackupSyncPeriod, ValidationFrequency time.Duration
	Config                                flag.Map
	Labels                                flag.Map
	CACertFile                            string
	AccessMode                            *flag.Enum
}

func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		Credential: flag.NewMap(),
		Config:     flag.NewMap(),
		Labels:     flag.NewMap(),
		AccessMode: flag.NewEnum(
			string(velerov1api.BackupStorageLocationAccessModeReadWrite),
			string(velerov1api.BackupStorageLocationAccessModeReadWrite),
			string(velerov1api.BackupStorageLocationAccessModeReadOnly),
		),
	}
}

func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.Provider, "provider", o.Provider, "Name of the backup storage provider (e.g. aws, azure, gcp).")
	flags.StringVar(&o.Bucket, "bucket", o.Bucket, "Name of the object storage bucket where backups should be stored.")
	flags.Var(&o.Credential, "credential", "The credential to be used by this location as a key-value pair, where the key is the Kubernetes Secret name, and the value is the data key name within the Secret. Optional, one value only.")
	flags.BoolVar(&o.DefaultBackupStorageLocation, "default", o.DefaultBackupStorageLocation, "Sets this new location to be the new default backup storage location. Optional.")
	flags.StringVar(&o.Prefix, "prefix", o.Prefix, "Prefix under which all Velero data should be stored within the bucket. Optional.")
	flags.DurationVar(&o.BackupSyncPeriod, "backup-sync-period", o.BackupSyncPeriod, "How often to ensure all Velero backups in object storage exist as Backup API objects in the cluster. Optional. Set this to `0s` to disable sync. Default: 1 minute.")
	flags.DurationVar(&o.ValidationFrequency, "validation-frequency", o.ValidationFrequency, "How often to verify if the backup storage location is valid. Optional. Set this to `0s` to disable sync. Default 1 minute.")
	flags.Var(&o.Config, "config", "Configuration key-value pairs.")
	flags.Var(&o.Labels, "labels", "Labels to apply to the backup storage location.")
	flags.StringVar(&o.CACertFile, "cacert", o.CACertFile, "File containing a certificate bundle to use when verifying TLS connections to the object store. Optional.")
	flags.Var(
		o.AccessMode,
		"access-mode",
		fmt.Sprintf("Access mode for the backup storage location. Valid values are %s", strings.Join(o.AccessMode.AllowedValues(), ",")),
	)
}

func (o *CreateOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if err := output.ValidateFlags(c); err != nil {
		return err
	}

	if o.Provider == "" {
		return errors.New("--provider is required")
	}

	if o.Bucket == "" {
		return errors.New("--bucket is required")
	}

	if o.BackupSyncPeriod < 0 {
		return errors.New("--backup-sync-period must be non-negative")
	}

	if len(o.Credential.Data()) > 1 {
		return errors.New("--credential can only contain 1 key/value pair")
	}

	return nil
}

func (o *CreateOptions) Complete(args []string, f client.Factory) error {
	o.Name = args[0]
	return nil
}

func (o *CreateOptions) BuildBackupStorageLocation(namespace string, setBackupSyncPeriod, setValidationFrequency bool) (*velerov1api.BackupStorageLocation, error) {
	var caCertData []byte
	if o.CACertFile != "" {
		realPath, err := filepath.Abs(o.CACertFile)
		if err != nil {
			return nil, err
		}
		caCertData, err = os.ReadFile(realPath)
		if err != nil {
			return nil, err
		}
	}

	backupStorageLocation := &velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      o.Name,
			Labels:    o.Labels.Data(),
		},
		Spec: velerov1api.BackupStorageLocationSpec{
			Provider: o.Provider,
			StorageType: velerov1api.StorageType{
				ObjectStorage: &velerov1api.ObjectStorageLocation{
					Bucket: o.Bucket,
					Prefix: o.Prefix,
					CACert: caCertData,
				},
			},
			Config:     o.Config.Data(),
			Default:    o.DefaultBackupStorageLocation,
			AccessMode: velerov1api.BackupStorageLocationAccessMode(o.AccessMode.String()),
		},
	}

	if setBackupSyncPeriod {
		backupStorageLocation.Spec.BackupSyncPeriod = &metav1.Duration{Duration: o.BackupSyncPeriod}
	}

	if setValidationFrequency {
		backupStorageLocation.Spec.ValidationFrequency = &metav1.Duration{Duration: o.ValidationFrequency}
	}

	for secretName, secretKey := range o.Credential.Data() {
		backupStorageLocation.Spec.Credential = builder.ForSecretKeySelector(secretName, secretKey).Result()
		break
	}

	return backupStorageLocation, nil
}

func (o *CreateOptions) Run(c *cobra.Command, f client.Factory) error {
	setBackupSyncPeriod := c.Flags().Changed("backup-sync-period")
	setValidationFrequency := c.Flags().Changed("validation-frequency")

	backupStorageLocation, err := o.BuildBackupStorageLocation(f.Namespace(), setBackupSyncPeriod, setValidationFrequency)
	if err != nil {
		return err
	}

	if printed, err := output.PrintWithFormat(c, backupStorageLocation); printed || err != nil {
		return err
	}

	kbClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	if o.DefaultBackupStorageLocation {
		// There is one and only one default backup storage location.
		// Disable any existing default backup storage location first.
		defalutBSLs, err := storage.GetDefaultBackupStorageLocations(context.Background(), kbClient, f.Namespace())
		if err != nil {
			return errors.WithStack(err)
		}
		if len(defalutBSLs.Items) > 0 {
			return errors.New("there is already exist default backup storage location, please unset it first or do not set --default flag")
		}
	}

	if err := kbClient.Create(context.Background(), backupStorageLocation, &kbclient.CreateOptions{}); err != nil {
		return errors.WithStack(err)
	}

	fmt.Printf("Backup storage location %q configured successfully.\n", backupStorageLocation.Name)
	return nil
}
