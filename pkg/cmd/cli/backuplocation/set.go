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

package backuplocation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

func NewSetCommand(f client.Factory, use string) *cobra.Command {
	o := NewSetOptions()

	c := &cobra.Command{
		Use:   use + " NAME",
		Short: "Set specific features for a backup storage location",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args, f))
			cmd.CheckError(o.Validate(c, args, f))
			cmd.CheckError(o.Run(c, f))
		},
	}

	c.ValidArgsFunction = cli.CompleteBackupStorageLocationNames(f)
	o.BindFlags(c.Flags())

	return c
}

type SetOptions struct {
	Name                         string
	CACertFile                   string
	Credential                   flag.Map
	DefaultBackupStorageLocation flag.OptionalBool
}

func NewSetOptions() *SetOptions {
	return &SetOptions{
		Credential: flag.NewMap(),
	}
}

func (o *SetOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.CACertFile, "cacert", o.CACertFile, "File containing a certificate bundle to use when verifying TLS connections to the object store. Optional.")
	flags.Var(&o.Credential, "credential", "Sets the credential to be used by this location as a key-value pair, where the key is the Kubernetes Secret name, and the value is the data key name within the Secret. Optional, one value only.")
	f := flags.VarPF(&o.DefaultBackupStorageLocation, "default", "", "Sets this new location to be the new default backup storage location. Optional.")
	f.NoOptDefVal = cmd.TRUE
}

func (o *SetOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if len(o.Credential.Data()) > 1 {
		return errors.New("--credential can only contain 1 key/value pair")
	}

	return nil
}

func (o *SetOptions) Complete(args []string, f client.Factory) error {
	o.Name = args[0]
	return nil
}

func (o *SetOptions) Run(c *cobra.Command, f client.Factory) error {
	kbClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	var caCertData []byte
	if o.CACertFile != "" {
		realPath, err := filepath.Abs(o.CACertFile)
		if err != nil {
			return err
		}
		caCertData, err = os.ReadFile(realPath)
		if err != nil {
			return err
		}
	}

	location := &velerov1api.BackupStorageLocation{}
	err = kbClient.Get(context.Background(), kbclient.ObjectKey{
		Namespace: f.Namespace(),
		Name:      o.Name,
	}, location)
	if err != nil {
		return errors.WithStack(err)
	}

	defaultOpt := o.DefaultBackupStorageLocation.Value
	if defaultOpt != nil {
		if *defaultOpt { // set default backup storage location
			// need first check if there is already a default backup storage location
			defalutBSLs, err := storage.GetDefaultBackupStorageLocations(context.Background(), kbClient, f.Namespace())
			if err != nil {
				return errors.WithStack(err)
			}
			if len(defalutBSLs.Items) > 0 {
				if len(defalutBSLs.Items) == 1 && defalutBSLs.Items[0].Name == o.Name {
					// the default backup storage location is the one we want to set
					// so we do not need to do anything
					fmt.Printf("Backup storage location %q is already the default backup storage location.\n", o.Name)
					return nil
				}
				return errors.New("there are already exist default backup storage locations, please unset them first")
			}
		}
	} else {
		// user do not specify default option
		// we should keep the original default option
		o.DefaultBackupStorageLocation = flag.OptionalBool{Value: &location.Spec.Default}
	}

	location.Spec.Default = boolptr.IsSetToTrue(o.DefaultBackupStorageLocation.Value)
	location.Spec.StorageType.ObjectStorage.CACert = caCertData

	for name, key := range o.Credential.Data() {
		location.Spec.Credential = builder.ForSecretKeySelector(name, key).Result()
		break
	}

	if err := kbClient.Update(context.Background(), location, &kbclient.UpdateOptions{}); err != nil {
		return errors.WithStack(err)
	}

	fmt.Printf("Backup storage location %q configured successfully.\n", o.Name)
	return nil
}
