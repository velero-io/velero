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

package itemoperationmap

import (
	"bytes"
	"sync"

	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
)

type RestoreItemOperationsMap struct {
	opsMap  map[string]*OperationsForRestore
	opsLock sync.Mutex
}

// Returns a pointer to a new RestoreItemOperationsMap
func NewRestoreItemOperationsMap() *RestoreItemOperationsMap {
	return &RestoreItemOperationsMap{opsMap: make(map[string]*OperationsForRestore)}
}

// returns a deep copy so we can minimize the time the map is locked
func (m *RestoreItemOperationsMap) GetOperationsForRestore(
	backupStore persistence.BackupStore,
	restoreName string) (*OperationsForRestore, error) {
	var err error
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	operations, ok := m.opsMap[restoreName]
	if !ok || len(operations.Operations) == 0 {
		operations = &OperationsForRestore{}
		operations.Operations, err = backupStore.GetRestoreItemOperations(restoreName)
		if err == nil {
			m.opsMap[restoreName] = operations
		}
	}
	return operations.DeepCopy(), err
}

func (m *RestoreItemOperationsMap) PutOperationsForRestore(
	operations *OperationsForRestore,
	restoreName string) {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()
	if operations != nil {
		m.opsMap[restoreName] = operations
	}
}

func (m *RestoreItemOperationsMap) DeleteOperationsForRestore(restoreName string) {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()
	delete(m.opsMap, restoreName)
}

// UploadProgressAndPutOperationsForRestore will upload the item operations for this restore to
// the object store and update the map for this restore with the modified operations
func (m *RestoreItemOperationsMap) UploadProgressAndPutOperationsForRestore(
	backupStore persistence.BackupStore,
	operations *OperationsForRestore,
	restoreName string) error {
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	if operations == nil {
		return errors.New("nil operations passed in")
	}
	if err := operations.uploadProgress(backupStore, restoreName); err != nil {
		return err
	}
	m.opsMap[restoreName] = operations
	return nil
}

// UpdateForRestore will upload the item operations for this restore to
// the object store, if it has changes not yet uploaded
func (m *RestoreItemOperationsMap) UpdateForRestore(backupStore persistence.BackupStore, restoreName string) error {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	operations, ok := m.opsMap[restoreName]
	// if operations for this restore aren't found, or if there are no changes
	// or errors since last update, do nothing
	if !ok || (!operations.ChangesSinceUpdate && len(operations.ErrsSinceUpdate) == 0) {
		return nil
	}
	if err := operations.uploadProgress(backupStore, restoreName); err != nil {
		return err
	}
	return nil
}

type OperationsForRestore struct {
	Operations         []*itemoperation.RestoreOperation
	ChangesSinceUpdate bool
	ErrsSinceUpdate    []string
}

func (m *OperationsForRestore) DeepCopy() *OperationsForRestore {
	if m == nil {
		return nil
	}
	out := new(OperationsForRestore)
	m.DeepCopyInto(out)
	return out
}

func (m *OperationsForRestore) DeepCopyInto(out *OperationsForRestore) {
	*out = *m
	if m.Operations != nil {
		in, out := &m.Operations, &out.Operations
		*out = make([]*itemoperation.RestoreOperation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(itemoperation.RestoreOperation)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if m.ErrsSinceUpdate != nil {
		in, out := &m.ErrsSinceUpdate, &out.ErrsSinceUpdate
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

func (m *OperationsForRestore) uploadProgress(backupStore persistence.BackupStore, restoreName string) error {
	if len(m.Operations) > 0 {
		var restoreItemOperations *bytes.Buffer
		restoreItemOperations, errs := encode.ToJSONGzip(m.Operations, "restore item operations list")
		if errs != nil {
			return errors.Wrap(errs[0], "error encoding item operations json")
		}
		err := backupStore.PutRestoreItemOperations(restoreName, restoreItemOperations)
		if err != nil {
			return errors.Wrap(err, "error uploading item operations json")
		}
	}
	m.ChangesSinceUpdate = false
	m.ErrsSinceUpdate = nil
	return nil
}
