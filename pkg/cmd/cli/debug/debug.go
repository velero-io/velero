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

package debug

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vmware-tanzu/crash-diagnostics/exec"
	appsv1api "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
)

//go:embed cshd-scripts/velero.cshd
var scriptBytes []byte

type option struct {
	// currCmd the velero command
	currCmd string
	// workdir for crashd will be $baseDir/velero-debug
	baseDir string
	// the namespace where velero server is installed
	namespace string
	// the absolute path for the log bundle to be generated
	outputPath string
	// the absolute path for the kubeconfig file that will be read by crashd for calling K8S API
	kubeconfigPath string
	// the kubecontext to be used for calling K8S API
	kubeContext string
	// optional, the name of the backup resource whose log will be packaged into the debug bundle
	backup string
	// optional, the name of the restore resource whose log will be packaged into the debug bundle
	restore string
	// optional, it controls whether to print the debug log messages when calling crashd
	verbose bool
}

func (o *option) bindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.outputPath, "output", "", "The path of the bundle tarball, by default it's ./bundle-<YYYY>-<MM>-<DD>-<HH>-<MM>-<SS>.tar.gz. Optional")
	flags.StringVar(&o.backup, "backup", "", "The name of the backup resource whose log will be collected, no backup logs will be collected if it's not set. Optional")
	flags.StringVar(&o.restore, "restore", "", "The name of the restore resource whose log will be collected, no restore logs will be collected if it's not set. Optional")
	flags.BoolVar(&o.verbose, "verbose", false, "When it's set to true the debug messages by crashd will be printed during execution.  Default value is false.")
}

func (o *option) asCrashdArgMap() exec.ArgMap {
	return exec.ArgMap{
		"cmd":         o.currCmd,
		"output":      o.outputPath,
		"namespace":   o.namespace,
		"basedir":     o.baseDir,
		"backup":      o.backup,
		"restore":     o.restore,
		"kubeconfig":  o.kubeconfigPath,
		"kubecontext": o.kubeContext,
	}
}

func (o *option) complete(f client.Factory, fs *pflag.FlagSet) error {
	if len(o.outputPath) == 0 {
		o.outputPath = fmt.Sprintf("./bundle-%s.tar.gz", time.Now().Format("2006-01-02-15-04-05"))
	}
	absOutputPath, err := filepath.Abs(o.outputPath)
	if err != nil {
		return fmt.Errorf("invalid output path: %v", err)
	}
	o.outputPath = absOutputPath
	tmpDir, err := os.MkdirTemp("", "crashd")
	if err != nil {
		return err
	}
	o.baseDir = tmpDir
	o.namespace = f.Namespace()
	kp, kc := kubeconfigAndContext(fs)
	o.currCmd, err = os.Executable()
	if err != nil {
		return err
	}
	o.kubeconfigPath, err = filepath.Abs(kp)
	if err != nil {
		return fmt.Errorf("invalid kubeconfig path: %s, %v", kp, err)
	}
	o.kubeContext = kc
	return nil
}

func (o *option) validate(f client.Factory) error {
	crClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}
	deploymentList := new(appsv1api.DeploymentList)
	selector, err := labels.Parse("component=velero")
	cmd.CheckError(err)
	err = crClient.List(context.TODO(), deploymentList, &ctrlclient.ListOptions{
		Namespace:     o.namespace,
		LabelSelector: selector,
	})
	if err != nil {
		return errors.Wrap(err, "failed to check velero deployment")
	}
	if len(deploymentList.Items) == 0 {
		return fmt.Errorf("velero deployment does not exist in namespace: %s", o.namespace)
	}
	if len(o.backup) > 0 {
		backup := new(velerov1api.Backup)
		if err := crClient.Get(context.TODO(), ctrlclient.ObjectKey{Namespace: o.namespace, Name: o.backup}, backup); err != nil {
			return err
		}
	}
	if len(o.restore) > 0 {
		restore := new(velerov1api.Restore)
		if err := crClient.Get(context.TODO(), ctrlclient.ObjectKey{Namespace: o.namespace, Name: o.restore}, restore); err != nil {
			return err
		}
	}
	return nil
}

// NewCommand creates a cobra command.
func NewCommand(f client.Factory) *cobra.Command {
	o := &option{}
	c := &cobra.Command{
		Use:   "debug",
		Short: "Generate debug bundle",
		Long: `Generate a tarball containing the logs of velero deployment, plugin logs, node-agent DaemonSet, 
specs of resources created by velero server, and optionally the logs of backup and restore.`,
		Run: func(c *cobra.Command, args []string) {
			flags := c.Flags()
			err := o.complete(f, flags)
			cmd.CheckError(err)
			defer func(opt *option) {
				if len(opt.baseDir) > 0 {
					if err := os.RemoveAll(opt.baseDir); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to remove temp dir: %s: %v\n", opt.baseDir, err)
					}
				}
			}(o)
			err = o.validate(f)
			cmd.CheckError(err)
			err = runCrashd(o)
			cmd.CheckError(err)
		},
	}
	o.bindFlags(c.Flags())
	return c
}

func runCrashd(o *option) error {
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to go back to workdir: %v", err)
		}
	}()
	if err := os.Chdir(o.baseDir); err != nil {
		return err
	}
	logrus.SetOutput(os.Stdout)
	if o.verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	return exec.Execute("velero-debug-collector", bytes.NewReader(scriptBytes), o.asCrashdArgMap(), false)
}

func kubeconfigAndContext(fs *pflag.FlagSet) (string, string) {
	pathOpt := clientcmd.NewDefaultPathOptions()
	kubeconfig, _ := fs.GetString("kubeconfig")
	if len(kubeconfig) > 0 {
		pathOpt.LoadingRules.ExplicitPath = kubeconfig
	}
	kubecontext, _ := fs.GetString("kubecontext")
	return pathOpt.GetDefaultFilename(), kubecontext
}
