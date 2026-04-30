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

package backup

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
		outputFormat          = "plaintext"
	)

	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}
	caCertFile := config.CACertFile()

	c := &cobra.Command{
		Use:   use + " [NAME1] [NAME2] [NAME...]",
		Short: "Describe backups",
		Run: func(c *cobra.Command, args []string) {
			kbClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			if outputFormat != "plaintext" && outputFormat != "json" {
				cmd.CheckError(fmt.Errorf("invalid output format '%s'. valid value are 'plaintext, json'", outputFormat))
			}

			backups := new(velerov1api.BackupList)
			if len(args) > 0 {
				for _, name := range args {
					backup := new(velerov1api.Backup)
					err := kbClient.Get(context.Background(), controllerclient.ObjectKey{Namespace: f.Namespace(), Name: name}, backup)
					cmd.CheckError(err)
					backups.Items = append(backups.Items, *backup)
				}
			} else {
				parsedSelector, err := labels.Parse(listOptions.LabelSelector)
				cmd.CheckError(err)
				err = kbClient.List(context.Background(), backups, &controllerclient.ListOptions{LabelSelector: parsedSelector, Namespace: f.Namespace()})
				cmd.CheckError(err)
			}

			first := true
			for i, backup := range backups.Items {
				deleteRequestList := new(velerov1api.DeleteBackupRequestList)
				err := kbClient.List(context.Background(), deleteRequestList, &controllerclient.ListOptions{
					Namespace:     f.Namespace(),
					LabelSelector: labels.SelectorFromSet(map[string]string{velerov1api.BackupNameLabel: label.GetValidName(backup.Name), velerov1api.BackupUIDLabel: string(backup.UID)}),
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "error getting DeleteBackupRequests for backup %s: %v\n", backup.Name, err)
				}

				podVolumeBackupList := new(velerov1api.PodVolumeBackupList)
				err = kbClient.List(context.Background(), podVolumeBackupList, &controllerclient.ListOptions{
					Namespace:     f.Namespace(),
					LabelSelector: labels.SelectorFromSet(map[string]string{velerov1api.BackupNameLabel: label.GetValidName(backup.Name)}),
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "error getting PodVolumeBackups for backup %s: %v\n", backup.Name, err)
				}

				// Inherit insecureSkipTLSVerify from BSL config if not set via CLI flag
				effectiveInsecureSkipTLS := insecureSkipTLSVerify
				bslInsecure, bslErr := cacert.GetInsecureSkipTLSVerifyFromBackup(context.Background(), kbClient, f.Namespace(), &backups.Items[i])
				if bslErr != nil {
					fmt.Fprintf(os.Stderr, "WARNING: Error getting insecureSkipTLSVerify from BSL for backup %s: %v\n", backup.Name, bslErr)
				}
				effectiveInsecureSkipTLS = effectiveInsecureSkipTLS || bslInsecure

				// structured output only applies to a single backup in case of OOM
				// To describe the list of backups in structured format, users could iterate over the list and describe backup one after another.
				if len(backups.Items) == 1 && outputFormat != "plaintext" {
					s := output.DescribeBackupInSF(context.Background(), kbClient, &backups.Items[i], deleteRequestList.Items, podVolumeBackupList.Items, details, effectiveInsecureSkipTLS, caCertFile, outputFormat)
					fmt.Print(s)
				} else {
					s := output.DescribeBackup(context.Background(), kbClient, &backups.Items[i], deleteRequestList.Items, podVolumeBackupList.Items, details, effectiveInsecureSkipTLS, caCertFile)
					if first {
						first = false
						fmt.Print(s)
					} else {
						fmt.Printf("\n\n%s", s)
					}
				}
			}
			cmd.CheckError(err)
		},
	}

	c.Flags().StringVarP(&listOptions.LabelSelector, "selector", "l", listOptions.LabelSelector, "Only show items matching this label selector.")
	c.Flags().BoolVar(&details, "details", details, "Display additional detail in the command output.")
	c.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", insecureSkipTLSVerify, "If true, the object store's TLS certificate will not be checked for validity. This is insecure and susceptible to man-in-the-middle attacks. Not recommended for production.")
	c.Flags().StringVar(&caCertFile, "cacert", caCertFile, "Path to a certificate bundle to use when verifying TLS connections. If not specified, the CA certificate from the BackupStorageLocation will be used if available.")
	c.Flags().StringVarP(&outputFormat, "output", "o", outputFormat, "Output display format. Valid formats are 'plaintext, json'. 'json' only applies to a single backup")

	return c
}
