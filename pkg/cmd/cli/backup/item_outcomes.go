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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/internal/itemoutcome"
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd"
	"github.com/velero-io/velero/pkg/cmd/cli"
	"github.com/velero-io/velero/pkg/cmd/util/cacert"
	"github.com/velero-io/velero/pkg/cmd/util/downloadrequest"
	"github.com/velero-io/velero/pkg/cmd/util/itemoutcomes"
)

type ItemOutcomesOptions struct {
	Timeout               time.Duration
	InsecureSkipTLSVerify bool
	CaCertFile            string
	Raw                   bool
	Output                string
	Client                kbclient.Client
	BackupName            string
	Namespace             string
}

func NewItemOutcomesOptions() ItemOutcomesOptions {
	config, err := client.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error reading config file: %v\n", err)
	}

	return ItemOutcomesOptions{
		Timeout:               time.Minute,
		InsecureSkipTLSVerify: false,
		CaCertFile:            config.CACertFile(),
	}
}

func (o *ItemOutcomesOptions) BindFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&o.Timeout, "timeout", o.Timeout, "How long to wait to receive the item outcomes artifact.")
	flags.BoolVar(&o.InsecureSkipTLSVerify, "insecure-skip-tls-verify", o.InsecureSkipTLSVerify, "If true, the object store's TLS certificate will not be checked for validity. This is insecure and susceptible to man-in-the-middle attacks. Not recommended for production.")
	flags.StringVar(&o.CaCertFile, "cacert", o.CaCertFile, "Path to a certificate bundle to use when verifying TLS connections. If not specified, the CA certificate from the BackupStorageLocation will be used if available.")
	flags.BoolVar(&o.Raw, "raw", o.Raw, "Print the compact, un-indented JSON as stored in object storage, instead of pretty-printing it.")
	flags.StringVarP(&o.Output, "output", "o", o.Output, "Output format: json or table. The default is json.")
}

func (o *ItemOutcomesOptions) Run(c *cobra.Command, f client.Factory) error {
	backup := new(velerov1api.Backup)
	err := o.Client.Get(context.Background(), kbclient.ObjectKey{Namespace: f.Namespace(), Name: o.BackupName}, backup)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("backup %q does not exist", o.BackupName)
	} else if err != nil {
		return fmt.Errorf("error checking for backup %q: %v", o.BackupName, err)
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(context.Background(), o.Client, f.Namespace(), backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		fmt.Fprintf(os.Stderr, "WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	err = downloadrequest.StreamWithBSLCACert(context.Background(), o.Client, f.Namespace(), o.BackupName, velerov1api.DownloadTargetKindBackupItemOutcomes, buf, o.Timeout, o.InsecureSkipTLSVerify, o.CaCertFile, bslCACert)
	if err == downloadrequest.ErrNotFound {
		return fmt.Errorf("item outcomes were not collected for backup %q", o.BackupName)
	}
	if err != nil {
		return err
	}

	if o.Raw {
		if o.Output == "table" {
			return fmt.Errorf("--raw cannot be combined with --output table")
		}
		// Warnings go to stderr so the raw bytes on stdout stay exactly as
		// stored. Decoding is best-effort: --raw must still print an artifact
		// this client cannot parse.
		var outcomes itemoutcome.ItemOutcomes
		if json.Unmarshal(buf.Bytes(), &outcomes) == nil {
			o.printWarnings(&outcomes, backup)
		}
		_, err = os.Stdout.Write(buf.Bytes())
		return err
	}

	var outcomes itemoutcome.ItemOutcomes
	if err := json.Unmarshal(buf.Bytes(), &outcomes); err != nil {
		return fmt.Errorf("error reading item outcomes: %v", err)
	}

	switch o.Output {
	case "", "json":
		o.printWarnings(&outcomes, backup)
		pretty, err := json.MarshalIndent(outcomes, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(pretty))
		return nil
	case "table":
		return o.printItems(&outcomes, backup)
	default:
		return fmt.Errorf("unsupported output format %q: use json or table", o.Output)
	}
}

// printWarnings reports the conditions that make the artifact an incomplete
// answer: backup-level errors with no row, an unfinalized artifact, an unknown
// schema, or an artifact from a different operation.
func (o *ItemOutcomesOptions) printWarnings(outcomes *itemoutcome.ItemOutcomes, backup *velerov1api.Backup) {
	// The artifact only covers items that were processed. A backup can fail while
	// listing resources, before any item exists, and then every item still reads
	// Succeeded. Say so rather than reporting the backup as clean.
	if backup != nil && backup.Status.Errors > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: backup %q recorded %d error(s), which need not belong to a listed item; "+
			"see `velero backup logs %s`.\n", backup.Name, backup.Status.Errors, backup.Name)
	}

	// An artifact written by a pre-refactor server (or by a backup that never
	// reached finalize) has no async-operation verdicts. Reporting it as clean
	// would present missing evidence as a clean bill of health.
	if !outcomes.Finalized {
		fmt.Fprintln(os.Stderr, "WARNING: this item outcomes artifact was not finalized; verdicts may be missing.")
	}

	// A newer schema may carry fields this client does not know how to read, and
	// an old client must not present a partial reading as complete.
	if !outcomes.SupportedSchemaVersion() {
		fmt.Fprintf(os.Stderr, "WARNING: this item outcomes artifact uses schema version %q, which this client does not understand (it understands %q). Output may be incomplete.\n",
			outcomes.SchemaVersion, itemoutcome.SchemaVersion)
	}

	// An artifact from another operation can share the envelope. Reading it as
	// backup outcomes would give its rows the wrong vocabulary.
	if outcomes.Kind != "" && outcomes.Kind != itemoutcome.KindBackup {
		fmt.Fprintf(os.Stderr, "WARNING: this artifact records %q outcomes, not backup outcomes.\n", outcomes.Kind)
	}
}

// printItems reports one row per item.
func (o *ItemOutcomesOptions) printItems(outcomes *itemoutcome.ItemOutcomes, backup *velerov1api.Backup) error {
	o.printWarnings(outcomes, backup)
	return itemoutcomes.PrintItems(os.Stdout, outcomes)
}

func (o *ItemOutcomesOptions) Complete(args []string, f client.Factory) error {
	if len(args) > 0 {
		o.BackupName = args[0]
	}

	kbClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}
	o.Client = kbClient
	o.Namespace = f.Namespace()
	return nil
}

func NewItemOutcomesCommand(f client.Factory) *cobra.Command {
	o := NewItemOutcomesOptions()

	c := &cobra.Command{
		Use:   "item-outcomes BACKUP",
		Short: "Get the per-item backup outcomes artifact",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			err := o.Complete(args, f)
			cmd.CheckError(err)

			err = o.Run(c, f)
			cmd.CheckError(err)
		},
	}

	c.ValidArgsFunction = cli.CompleteBackupNames(f)
	o.BindFlags(c.Flags())

	return c
}
