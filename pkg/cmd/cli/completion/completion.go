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

package completion

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:

$ source <(velero completion bash)

# To load completions for each session, execute once:
Linux:
	$ velero completion bash > /etc/bash_completion.d/velero
MacOS:
	$ velero completion bash > /usr/local/etc/bash_completion.d/velero

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ velero completion zsh > "${fpath[1]}/_velero"

# You will need to start a new shell for this setup to take effect.

Fish:

$ velero completion fish | source

# To load completions for each session, execute once:
$ velero completion fish > ~/.config/fish/completions/velero.fish
`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		Run: func(cmd *cobra.Command, args []string) {
			shell := args[0]
			switch shell {
			case "bash":
				if err := cmd.Root().GenBashCompletionV2(os.Stdout, true); err != nil {
					fmt.Println("fail to generate bash completion script", err)
					os.Exit(1)
				}
			case "zsh":
				// # fix #4912
				// cobra does not support zsh completion ouptput used by source command
				// according to https://github.com/spf13/cobra/issues/1529
				// Need to append compdef manually to do that.
				zshHead := "#compdef velero\ncompdef _velero velero\n"
				out := os.Stdout
				if _, err := out.Write([]byte(zshHead)); err != nil {
					fmt.Println("fail to append compdef command into zsh completion script: ", err)
					os.Exit(1)
				}

				if err := cmd.Root().GenZshCompletion(out); err != nil {
					fmt.Println("fail to generate zsh completion script: ", err)
					os.Exit(1)
				}
			case "fish":
				if err := cmd.Root().GenFishCompletion(os.Stdout, true); err != nil {
					fmt.Println("fail to generate fish completion script: ", err)
					os.Exit(1)
				}
			default:
				fmt.Println("Invalid shell specified, specify bash, zsh, or fish")
				os.Exit(1)
			}
		},
	}

	return c
}
