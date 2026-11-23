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

package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd/util/confirm"
)

// DeleteOptions contains parameters used for deleting a restore.
type DeleteOptions struct {
	*SelectOptions
	confirm.ConfirmOptions
	Client    controllerclient.Client
	Namespace string
}

func NewDeleteOptions(singularTypeName string) *DeleteOptions {
	o := &DeleteOptions{}
	o.ConfirmOptions = *confirm.NewConfirmOptionsWithDescription("Confirm deletion")
	o.SelectOptions = NewSelectOptions("delete", singularTypeName)
	return o
}

// Complete fills in the correct values for all the options.
func (o *DeleteOptions) Complete(f client.Factory, args []string) error {
	o.Namespace = f.Namespace()
	client, err := f.KubebuilderClient()
	if err != nil {
		return err
	}
	o.Client = client
	return o.SelectOptions.Complete(args)
}

// Validate validates the fields of the DeleteOptions struct.
func (o *DeleteOptions) Validate(c *cobra.Command, f client.Factory, args []string) error {
	if o.Client == nil {
		return errors.New("velero client is not set; unable to proceed")
	}

	return o.SelectOptions.Validate()
}

// BindFlags binds options for this command to flags.
func (o *DeleteOptions) BindFlags(flags *pflag.FlagSet) {
	o.ConfirmOptions.BindFlags(flags)
	o.SelectOptions.BindFlags(flags)
}

// Xor returns true if exactly one of the provided values is true,
// or false otherwise.
func xor(val bool, vals ...bool) bool {
	res := val

	for _, v := range vals {
		if res && v {
			return false
		}
		res = res || v
	}
	return res
}
