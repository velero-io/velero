/*
Copyright 2021 the Velero contributors.

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

package velero

import (
	"flag"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/velero/pkg/cmd/cli/debug"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/podvolume"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/repomantenance"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/backup"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/backuplocation"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/bug"
	cliclient "github.com/vmware-tanzu/velero/pkg/cmd/cli/client"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/completion"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/create"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/delete"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/describe"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/get"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/install"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/plugin"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/repo"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/restore"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/schedule"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/snapshotlocation"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/uninstall"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/version"
	"github.com/vmware-tanzu/velero/pkg/cmd/server"
	runplugin "github.com/vmware-tanzu/velero/pkg/cmd/server/plugin"
	veleroflag "github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/features"

	"github.com/vmware-tanzu/velero/pkg/cmd/cli/datamover"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/nodeagent"
)

func NewCommand(name string) *cobra.Command {
	// Load the config here so that we can extract features from it.
	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}

	// Declare cmdFeatures and cmdColorzied here so we can access them in the PreRun hooks
	// without doing a chain of calls into the command's FlagSet
	var cmdFeatures veleroflag.StringArray
	var cmdColorzied veleroflag.OptionalBool

	c := &cobra.Command{
		Use:   name,
		Short: "Back up and restore Kubernetes cluster resources.",
		Long: `Velero is a tool for managing disaster recovery, specifically for Kubernetes
cluster resources. It provides a simple, configurable, and operationally robust
way to back up your application state and associated data.

If you're familiar with kubectl, Velero supports a similar model, allowing you to
execute commands such as 'velero get backup' and 'velero create schedule'. The same
operations can also be performed as 'velero backup get' and 'velero schedule create'.`,
		// PersistentPreRun will run before all subcommands EXCEPT in the following conditions:
		//  - a subcommand defines its own PersistentPreRun function
		//  - the command is run without arguments or with --help and only prints the usage info
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			features.Enable(config.Features()...)
			features.Enable(cmdFeatures...)

			switch {
			case cmdColorzied.Value != nil:
				color.NoColor = !*cmdColorzied.Value
			default:
				color.NoColor = !config.Colorized()
			}
		},
	}

	f := client.NewFactory(name, config)
	f.BindFlags(c.PersistentFlags())

	// Bind features directly to the root command so it's available to all callers.
	c.PersistentFlags().Var(&cmdFeatures, "features", "Comma-separated list of features to enable for this Velero process. Combines with values from $HOME/.config/velero/config.json if present")

	// Color will be enabled or disabled for all subcommands
	c.PersistentFlags().Var(&cmdColorzied, "colorized", "Show colored output in TTY. Overrides 'colorized' value from $HOME/.config/velero/config.json if present. Enabled by default")

	c.AddCommand(
		backup.NewCommand(f),
		schedule.NewCommand(f),
		restore.NewCommand(f),
		server.NewCommand(f),
		nodeagent.NewCommand(f),
		version.NewCommand(f),
		get.NewCommand(f),
		install.NewCommand(f),
		uninstall.NewCommand(f),
		describe.NewCommand(f),
		create.NewCommand(f),
		runplugin.NewCommand(f),
		plugin.NewCommand(f),
		delete.NewCommand(f),
		cliclient.NewCommand(),
		completion.NewCommand(),
		repo.NewCommand(f),
		bug.NewCommand(),
		backuplocation.NewCommand(f),
		snapshotlocation.NewCommand(f),
		debug.NewCommand(f),
		repomantenance.NewCommand(f),
		datamover.NewCommand(f),
		podvolume.NewCommand(f),
	)

	// init and add the klog flags
	klog.InitFlags(flag.CommandLine)
	// Opt into the new klog behavior so that -stderrthreshold is honored even
	// when -logtostderr=true (the default).
	// Ref: kubernetes/klog#212, kubernetes/klog#432
	flag.CommandLine.Set("legacy_stderr_threshold_behavior", "false") //nolint:errcheck // flag is registered by klog.InitFlags above
	flag.CommandLine.Set("stderrthreshold", "INFO")                   //nolint:errcheck // flag is registered by klog.InitFlags above
	c.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	return c
}
