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
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/itemoperation"
)

func TestRequest_BackupResourceList(t *testing.T) {
	items := []itemKey{
		{
			resource:  "apps/v1/Deployment",
			name:      "my-deploy",
			namespace: "default",
		},
		{
			resource:  "v1/Pod",
			name:      "pod1",
			namespace: "ns1",
		},
		{
			resource:  "v1/Pod",
			name:      "pod2",
			namespace: "ns2",
		},
		{
			resource: "v1/PersistentVolume",
			name:     "my-pv",
		},
	}
	backedUpItems := NewBackedUpItemsMap()
	for _, it := range items {
		backedUpItems.AddItem(it)
	}

	req := Request{BackedUpItems: backedUpItems}
	assert.Equal(t, map[string][]string{
		"apps/v1/Deployment":  {"default/my-deploy"},
		"v1/Pod":              {"ns1/pod1", "ns2/pod2"},
		"v1/PersistentVolume": {"my-pv"},
	}, req.BackupResourceList())
}

func TestRequest_BackupResourceListEntriesSorted(t *testing.T) {
	items := []itemKey{
		{
			resource:  "v1/Pod",
			name:      "pod2",
			namespace: "ns2",
		},
		{
			resource:  "v1/Pod",
			name:      "pod1",
			namespace: "ns1",
		},
	}
	backedUpItems := NewBackedUpItemsMap()
	for _, it := range items {
		backedUpItems.AddItem(it)
	}

	req := Request{BackedUpItems: backedUpItems}
	assert.Equal(t, map[string][]string{
		"v1/Pod": {"ns1/pod1", "ns2/pod2"},
	}, req.BackupResourceList())
}

func TestRequest_AddItemOperationConcurrent(t *testing.T) {
	const (
		goroutines   = 8
		perGoroutine = 100
	)

	req := &Request{}
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				req.AddItemOperation(&itemoperation.BackupOperation{
					Spec: itemoperation.BackupOperationSpec{OperationID: fmt.Sprintf("%d-%d", g, i)},
				})
			}
		}()
	}
	wg.Wait()

	operations := *req.GetItemOperationsList()
	require.Len(t, operations, goroutines*perGoroutine)
	for _, operation := range operations {
		require.NotNil(t, operation)
	}
}
