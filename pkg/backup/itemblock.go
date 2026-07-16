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
	"encoding/json"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/pkg/itemblock"
)

type BackupItemBlock struct {
	itemblock.ItemBlock
	// This is a reference to the  shared itemBackupper for the backup
	itemBackupper *itemBackupper
}

func NewBackupItemBlock(log logrus.FieldLogger, itemBackupper *itemBackupper) *BackupItemBlock {
	return &BackupItemBlock{
		ItemBlock:     itemblock.ItemBlock{Log: log},
		itemBackupper: itemBackupper,
	}
}

func (b *BackupItemBlock) addKubernetesResource(item *kubernetesResource, log logrus.FieldLogger) *unstructured.Unstructured {
	// no-op if item has already been processed (in a block or previously excluded)
	if item.inItemBlockOrExcluded {
		return nil
	}
	var unstructured unstructured.Unstructured
	item.inItemBlockOrExcluded = true

	f, err := os.Open(item.path)
	if err != nil {
		log.WithError(errors.WithStack(err)).Error("Error opening file containing item")
		return nil
	}
	defer f.Close()
	defer os.Remove(f.Name())

	if err := json.NewDecoder(f).Decode(&unstructured); err != nil {
		log.WithError(errors.WithStack(err)).Error("Error decoding JSON from file")
		return nil
	}

	metadata, err := meta.Accessor(&unstructured)
	if err != nil {
		log.WithError(errors.WithStack(err)).Warn("Error accessing item metadata")
		return nil
	}
	// Don't add to ItemBlock if item is excluded
	// itemInclusionChecks logs the reason
	if !b.itemBackupper.itemInclusionChecks(log, false, metadata, &unstructured, item.groupResource) {
		return nil
	}

	log.Infof("adding %s %s/%s to ItemBlock", item.groupResource, item.namespace, item.name)
	b.AddUnstructured(item.groupResource, &unstructured, item.preferredGVR)
	return &unstructured
}
