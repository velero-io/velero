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

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
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

	o.BindFlags(c.Flags())

	return c
}

type SetOptions struct {
	Name                         string
	CACertFile                   string
	Credential                   flag.Map
	DefaultBackupStorageLocation bool
}

func NewSetOptions() *SetOptions {
	return &SetOptions{
		Credential: flag.NewMap(),
	}
}

func (o *SetOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.CACertFile, "cacert", o.CACertFile, "File containing a certificate bundle to use when verifying TLS connections to the object store. Optional.")
	flags.Var(&o.Credential, "credential", "Sets the credential to be used by this location as a key-value pair, where the key is the Kubernetes Secret name, and the value is the data key name within the Secret. Optional, one value only.")
	flags.BoolVar(&o.DefaultBackupStorageLocation, "default", o.DefaultBackupStorageLocation, "Sets this new location to be the new default backup storage location. Optional.")
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

	if o.DefaultBackupStorageLocation {
		// There is one and only one default backup storage location.
		// Disable the origin default backup storage location.
		locations := new(velerov1api.BackupStorageLocationList)
		if err := kbClient.List(context.Background(), locations, &kbclient.ListOptions{Namespace: f.Namespace()}); err != nil {
			return errors.WithStack(err)
		}
		for i, location := range locations.Items {
			if !location.Spec.Default {
				continue
			}
			if location.Name == o.Name {
				// Do not update if the origin default BSL is the current one.
				break
			}
			location.Spec.Default = false
			if err := kbClient.Update(context.Background(), &locations.Items[i], &kbclient.UpdateOptions{}); err != nil {
				return errors.WithStack(err)
			}
			break
		}
	}

	location.Spec.Default = o.DefaultBackupStorageLocation
	location.Spec.ObjectStorage.CACert = caCertData

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
