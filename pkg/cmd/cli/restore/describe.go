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

package restore

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
	"github.com/vmware-tanzu/velero/pkg/label"
)

func NewDescribeCommand(f client.Factory, use string) *cobra.Command {
	var (
		listOptions           metav1.ListOptions
		details               bool
		insecureSkipTLSVerify bool
	)

	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}
	caCertFile := config.CACertFile()

	c := &cobra.Command{
		Use:   use + " [NAME1] [NAME2] [NAME...]",
		Short: "Describe restores",
		Run: func(c *cobra.Command, args []string) {
			kbClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			restoreList := new(velerov1api.RestoreList)
			if len(args) > 0 {
				for _, name := range args {
					restore := new(velerov1api.Restore)
					err := kbClient.Get(context.TODO(), controllerclient.ObjectKey{Namespace: f.Namespace(), Name: name}, restore)
					cmd.CheckError(err)
					restoreList.Items = append(restoreList.Items, *restore)
				}
			} else {
				parsedSelector, err := labels.Parse(listOptions.LabelSelector)
				cmd.CheckError(err)

				err = kbClient.List(context.TODO(), restoreList, &controllerclient.ListOptions{LabelSelector: parsedSelector, Namespace: f.Namespace()})
				cmd.CheckError(err)
			}

			first := true
			for i, restore := range restoreList.Items {
				podVolumeRestoreList := new(velerov1api.PodVolumeRestoreList)
				err = kbClient.List(context.TODO(), podVolumeRestoreList, &controllerclient.ListOptions{
					Namespace:     f.Namespace(),
					LabelSelector: labels.SelectorFromSet(map[string]string{velerov1api.RestoreNameLabel: label.GetValidName(restore.Name)}),
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "error getting PodVolumeRestores for restore %s: %v\n", restore.Name, err)
				}

				// Inherit insecureSkipTLSVerify from BSL config if not set via CLI flag
				effectiveInsecureSkipTLS := insecureSkipTLSVerify
				bslInsecure, bslErr := cacert.GetInsecureSkipTLSVerifyFromRestore(context.Background(), kbClient, f.Namespace(), &restoreList.Items[i])
				if bslErr != nil {
					fmt.Fprintf(os.Stderr, "WARNING: Error getting insecureSkipTLSVerify from BSL for restore %s: %v\n", restore.Name, bslErr)
				}
				effectiveInsecureSkipTLS = effectiveInsecureSkipTLS || bslInsecure

				s := output.DescribeRestore(context.Background(), kbClient, &restoreList.Items[i], podVolumeRestoreList.Items, details, effectiveInsecureSkipTLS, caCertFile)
				if first {
					first = false
					fmt.Print(s)
				} else {
					fmt.Printf("\n\n%s", s)
				}
			}
			cmd.CheckError(err)
		},
	}

	c.Flags().StringVarP(&listOptions.LabelSelector, "selector", "l", listOptions.LabelSelector, "Only show items matching this label selector.")
	c.Flags().BoolVar(&details, "details", details, "Display additional detail in the command output.")
	c.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", insecureSkipTLSVerify, "If true, the object store's TLS certificate will not be checked for validity. This is insecure and susceptible to man-in-the-middle attacks. Not recommended for production.")
	c.Flags().StringVar(&caCertFile, "cacert", caCertFile, "Path to a certificate bundle to use when verifying TLS connections.")

	return c
}
