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

package itemoutcomes

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/velero-io/velero/internal/itemoutcome"
)

// PrintItems writes one row per item. It is the first-tier read surface:
// identity and outcome, so a user can find which item failed without reading
// the backup log.
func PrintItems(w io.Writer, outcomes *itemoutcome.ItemOutcomes) error {
	items := []itemoutcome.ItemOutcome{}
	if outcomes != nil {
		items = append(items, outcomes.Items...)
	}
	if len(items) == 0 {
		fmt.Fprintln(w, "No items were recorded.")
		return nil
	}

	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.GroupResource != b.GroupResource {
			return a.GroupResource < b.GroupResource
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join([]string{"GROUP/RESOURCE", "NAMESPACE", "NAME", "OUTCOME", "MESSAGES"}, "\t"))
	for _, item := range items {
		namespace := item.Namespace
		if namespace == "" {
			namespace = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n",
			item.GroupResource,
			namespace,
			item.Name,
			itemoutcome.OutcomeLabel(item.Outcome),
			len(item.Messages),
		)
	}
	return tw.Flush()
}
