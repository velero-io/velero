/*
Copyright 2018 the Velero contributors.

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

package bug

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/buildinfo"
	"github.com/velero-io/velero/pkg/cmd"
	"github.com/velero-io/velero/pkg/features"
)

const (
	// kubectlTimeout is how long we wait in seconds for `kubectl version`
	// before killing the process
	kubectlTimeout = 5 * time.Second
	issueURL       = "https://github.com/velero-io/velero/issues/new"
	// IssueTemplate is used to generate .github/ISSUE_TEMPLATE/bug_report.md
	// as well as the initial text that's place in a new Github issue as
	// the result of running `velero bug`.
	IssueTemplate = `---
name: Bug report
about: Tell us about a problem you are experiencing

---

**What steps did you take and what happened:**
<!--A clear and concise description of what the bug is, and what commands you ran.-->


**What did you expect to happen:**

**The following information will help us better understand what's going on**:

_If you are using velero v1.7.0+:_  
Please use ` + "`velero debug  --backup <backupname> --restore <restorename>` " +
		`to generate the support bundle, and attach to this issue, more options please refer to ` +
		"`velero debug --help` " + `

_If you are using earlier versions:_  
Please provide the output of the following commands (Pasting long output into a [GitHub gist](https://gist.github.com) or other pastebin is fine.)
- ` + "`kubectl logs deployment/velero -n velero`" + `
- ` + "`velero backup describe <backupname>` or `kubectl get backup/<backupname> -n velero -o yaml`" + `
- ` + "`velero backup logs <backupname>`" + `
- ` + "`velero restore describe <restorename>` or `kubectl get restore/<restorename> -n velero -o yaml`" + `
- ` + "`velero restore logs <restorename>`" + `


**Anything else you would like to add:**
<!--Miscellaneous information that will assist in solving the issue.-->


**Environment:**

- Velero version (use ` + "`velero version`" + `):{{.VeleroVersion}} {{.GitCommit}}
- Velero features (use ` + "`velero client config get features`" + `): {{.Features}}
- Kubernetes version (use ` + "`kubectl version`" + `): 
{{- if .KubectlVersion}}
` + "```" + `
{{.KubectlVersion}}
` + "```" + `
{{end}}
- Kubernetes installer & version:
- Cloud provider or hardware configuration:
- OS (e.g. from ` + "`/etc/os-release`" + `):
{{- if .RuntimeOS}} - RuntimeOS: {{.RuntimeOS}}{{end}}
{{- if .RuntimeArch}} - RuntimeArch: {{.RuntimeArch}}{{end}}


**Vote on this issue!**

This is an invitation to the Velero community to vote on issues, you can see the project's [top voted issues listed here](https://github.com/velero-io/velero/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc).  
Use the "reaction smiley face" up to the right of this comment to vote.

- :+1: for "I would like to see this bug fixed as soon as possible"
- :-1: for "There are more important bugs to focus on right now"
`
)

func NewCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "bug",
		Short: "Report a Velero bug",
		Long:  "Open a browser window to report a Velero bug",
		Run: func(c *cobra.Command, args []string) {
			kubectlVersion, err := getKubectlVersion()
			if err != nil {
				// we don't want to prevent the user from submitting a bug
				// if we can't get the kubectl version, so just display a warning
				fmt.Fprintf(os.Stderr, "WARNING: can't get kubectl version: %v\n", err)
			}
			body, err := renderToString(newBugInfo(kubectlVersion))
			cmd.CheckError(err)
			cmd.CheckError(showIssueInBrowser(body))
		},
	}
	return c
}

type VeleroBugInfo struct {
	VeleroVersion  string
	GitCommit      string
	RuntimeOS      string
	RuntimeArch    string
	KubectlVersion string
	Features       string
}

// cmdExistsOnPath checks to see if an executable is available on the current PATH
func cmdExistsOnPath(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}

// getKubectlVersion makes a best-effort to run `kubectl version`
// and return it's output. This func will timeout and return an empty
// string after kubectlTimeout if we're not connected to a cluster.
func getKubectlVersion() (string, error) {
	if !cmdExistsOnPath("kubectl") {
		return "", errors.New("kubectl not found on PATH")
	}

	kubectlCmd := exec.CommandContext(context.Background(), "kubectl", "version")
	var outbuf bytes.Buffer
	kubectlCmd.Stdout = &outbuf
	if err := kubectlCmd.Start(); err != nil {
		return "", errors.New("can't start kubectl")
	}

	done := make(chan error, 1)
	go func() {
		done <- kubectlCmd.Wait()
	}()
	select {
	case <-time.After(kubectlTimeout):
		// we don't care about the possible error returned from Kill() here,
		// just return an empty string
		if err := kubectlCmd.Process.Kill(); err != nil {
			return "", fmt.Errorf("error killing kubectl process: %w", err)
		}
		return "", errors.New("timeout waiting for kubectl version")

	case err := <-done:
		if err != nil {
			return "", errors.New("error waiting for kubectl process")
		}
	}
	versionOut := outbuf.String()
	kubectlVersion := strings.TrimSpace(versionOut)
	return kubectlVersion, nil
}

func newBugInfo(kubectlVersion string) *VeleroBugInfo {
	return &VeleroBugInfo{
		VeleroVersion:  buildinfo.Version,
		GitCommit:      buildinfo.FormattedGitSHA(),
		RuntimeOS:      runtime.GOOS,
		RuntimeArch:    runtime.GOARCH,
		KubectlVersion: kubectlVersion,
		Features:       features.Serialize(),
	}
}

// renderToString renders IssueTemplate to a string using the
// supplied *VeleroBugInfo
func renderToString(bugInfo *VeleroBugInfo) (string, error) {
	outputTemplate, err := template.New("ghissue").Parse(IssueTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = outputTemplate.Execute(&buf, bugInfo)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// showIssueInBrowser opens a browser window to submit a Github issue using
// a platform specific binary.
func showIssueInBrowser(body string) error {
	url := issueURL + "?body=" + url.QueryEscape(body)
	ctx := context.Background()
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "open", url).Start()
	case "linux":
		if cmdExistsOnPath("xdg-open") {
			return exec.CommandContext(ctx, "xdg-open", url).Start()
		}
		return fmt.Errorf("velero can't open a browser window using the command '%s'", "xdg-open")
	case "windows":
		return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("velero can't open a browser window on platform %s", runtime.GOOS)
	}
}
