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

package snapshotlocation

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
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
		Short: "Create a volume snapshot location",
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
	Name       string
	Provider   string
	Config     flag.Map
	Labels     flag.Map
	Credential flag.Map
}

func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		Config:     flag.NewMap(),
		Labels:     flag.NewMap(),
		Credential: flag.NewMap(),
	}
}

func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.Provider, "provider", o.Provider, "Name of the volume snapshot provider (e.g. aws, azure, gcp).")
	flags.Var(&o.Config, "config", "Configuration key-value pairs.")
	flags.Var(&o.Labels, "labels", "Labels to apply to the volume snapshot location.")
	flags.Var(&o.Credential, "credential", "The credential to be used by this location as a key-value pair, where the key is the Kubernetes Secret name, and the value is the data key name within the Secret. Optional, one value only.")
}

func (o *CreateOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if err := output.ValidateFlags(c); err != nil {
		return err
	}

	if o.Provider == "" {
		return errors.New("--provider is required")
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

func (o *CreateOptions) BuildVolumeSnapshotLocation(namespace string) *api.VolumeSnapshotLocation {
	volumeSnapshotLocation := &api.VolumeSnapshotLocation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      o.Name,
			Labels:    o.Labels.Data(),
		},
		Spec: api.VolumeSnapshotLocationSpec{
			Provider: o.Provider,
			Config:   o.Config.Data(),
		},
	}
	for secretName, secretKey := range o.Credential.Data() {
		volumeSnapshotLocation.Spec.Credential = builder.ForSecretKeySelector(secretName, secretKey).Result()
		break
	}
	return volumeSnapshotLocation
}

func (o *CreateOptions) Run(c *cobra.Command, f client.Factory) error {
	volumeSnapshotLocation := o.BuildVolumeSnapshotLocation(f.Namespace())

	if printed, err := output.PrintWithFormat(c, volumeSnapshotLocation); printed || err != nil {
		return err
	}

	client, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	if err := client.Create(context.TODO(), volumeSnapshotLocation); err != nil {
		return errors.WithStack(err)
	}

	fmt.Printf("Snapshot volume location %q configured successfully.\n", volumeSnapshotLocation.Name)
	return nil
}
