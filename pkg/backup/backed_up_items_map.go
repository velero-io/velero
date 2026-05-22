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
	"maps"
	"sort"
	"sync"
)

// backedUpItemsMap keeps track of the items already backed up for the current Velero Backup
type backedUpItemsMap struct {
	*sync.RWMutex
	backedUpItems map[itemKey]struct{}
	totalItems    map[itemKey]struct{}
}

func NewBackedUpItemsMap() *backedUpItemsMap {
	return &backedUpItemsMap{
		RWMutex:       &sync.RWMutex{},
		backedUpItems: make(map[itemKey]struct{}),
		totalItems:    make(map[itemKey]struct{}),
	}
}

func (m *backedUpItemsMap) CopyItemMap() map[itemKey]struct{} {
	m.RLock()
	defer m.RUnlock()
	returnMap := make(map[itemKey]struct{}, len(m.backedUpItems))
	maps.Copy(returnMap, m.backedUpItems)
	return returnMap
}

// ResourceMap returns a map of the backed up items.
// For each map entry, the key is the resource type,
// and the value is a list of namespaced names for the resource.
func (m *backedUpItemsMap) ResourceMap() map[string][]string {
	m.RLock()
	defer m.RUnlock()

	resources := map[string][]string{}
	for i := range m.backedUpItems {
		entry := i.name
		if i.namespace != "" {
			entry = fmt.Sprintf("%s/%s", i.namespace, i.name)
		}
		resources[i.resource] = append(resources[i.resource], entry)
	}

	// sort namespace/name entries for each GVK
	for _, v := range resources {
		sort.Strings(v)
	}

	return resources
}

func (m *backedUpItemsMap) Len() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.backedUpItems)
}

func (m *backedUpItemsMap) BackedUpAndTotalLen() (int, int) {
	m.RLock()
	defer m.RUnlock()
	return len(m.backedUpItems), len(m.totalItems)
}

func (m *backedUpItemsMap) Has(key itemKey) bool {
	m.RLock()
	defer m.RUnlock()

	_, exists := m.backedUpItems[key]
	return exists
}

func (m *backedUpItemsMap) AddItem(key itemKey) {
	m.Lock()
	defer m.Unlock()
	m.backedUpItems[key] = struct{}{}
	m.totalItems[key] = struct{}{}
}

func (m *backedUpItemsMap) DeleteItem(key itemKey) {
	m.Lock()
	defer m.Unlock()

	delete(m.backedUpItems, key)
	delete(m.totalItems, key)
}

func (m *backedUpItemsMap) AddItemToTotal(key itemKey) {
	m.Lock()
	defer m.Unlock()
	m.totalItems[key] = struct{}{}
}
