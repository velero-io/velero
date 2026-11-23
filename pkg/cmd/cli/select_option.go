/*
Copyright The Velero Contributors.

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

	"github.com/spf13/pflag"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/velero-io/velero/pkg/cmd/util/flag"
)

// SelectOptions defines the options for selecting resources
type SelectOptions struct {
	Names            []string
	All              bool
	Selector         flag.LabelSelector
	CMD              string
	SingularTypeName string
}

// NewSelectOptions creates a new option for selector
func NewSelectOptions(cmd, singularTypeName string) *SelectOptions {
	return &SelectOptions{
		CMD:              cmd,
		SingularTypeName: singularTypeName,
	}
}

// Complete fills in the correct values for all the options.
func (o *SelectOptions) Complete(args []string) error {
	o.Names = args
	return nil
}

// Validate validates the fields of the SelectOptions struct.
func (o *SelectOptions) Validate() error {
	var (
		hasNames    = len(o.Names) > 0
		hasAll      = o.All
		hasSelector = o.Selector.LabelSelector != nil
	)
	if !xor(hasNames, hasAll, hasSelector) {
		return errors.New("you must specify exactly one of: specific " + o.SingularTypeName + " name(s), the --all flag, or the --selector flag")
	}

	return nil
}

// BindFlags binds options for this command to flags.
func (o *SelectOptions) BindFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&o.All, "all", o.All, cases.Title(language.Und).String(o.CMD)+" all "+o.SingularTypeName+"s")
	flags.VarP(&o.Selector, "selector", "l", cases.Title(language.Und).String(o.CMD)+" all "+o.SingularTypeName+"s matching this label selector.")
}
