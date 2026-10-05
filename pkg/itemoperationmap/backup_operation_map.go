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

type BackupItemOperationsMap struct {
	opsMap  map[string]*OperationsForBackup
	opsLock sync.Mutex
}

// Returns a pointer to a new BackupItemOperationsMap
func NewBackupItemOperationsMap() *BackupItemOperationsMap {
	return &BackupItemOperationsMap{opsMap: make(map[string]*OperationsForBackup)}
}

// returns a deep copy so we can minimize the time the map is locked
func (m *BackupItemOperationsMap) GetOperationsForBackup(
	backupStore persistence.BackupStore,
	backupName string) (*OperationsForBackup, error) {
	var err error
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	operations, ok := m.opsMap[backupName]
	if !ok || len(operations.Operations) == 0 {
		operations = &OperationsForBackup{}
		operations.Operations, err = backupStore.GetBackupItemOperations(backupName)
		if err == nil {
			m.opsMap[backupName] = operations
		}
	}
	return operations.DeepCopy(), err
}

func (m *BackupItemOperationsMap) PutOperationsForBackup(
	operations *OperationsForBackup,
	backupName string) {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()
	if operations != nil {
		m.opsMap[backupName] = operations
	}
}

func (m *BackupItemOperationsMap) DeleteOperationsForBackup(backupName string) {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()
	delete(m.opsMap, backupName)
}

// UploadProgressAndPutOperationsForBackup will upload the item operations for this backup to
// the object store and update the map for this backup with the modified operations
func (m *BackupItemOperationsMap) UploadProgressAndPutOperationsForBackup(
	backupStore persistence.BackupStore,
	operations *OperationsForBackup,
	backupName string) error {
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	if operations == nil {
		return errors.New("nil operations passed in")
	}
	if err := operations.uploadProgress(backupStore, backupName); err != nil {
		return err
	}
	m.opsMap[backupName] = operations
	return nil
}

// UpdateForBackup will upload the item operations for this backup to
// the object store, if it has changes not yet uploaded
func (m *BackupItemOperationsMap) UpdateForBackup(backupStore persistence.BackupStore, backupName string) error {
	// lock operations map
	m.opsLock.Lock()
	defer m.opsLock.Unlock()

	operations, ok := m.opsMap[backupName]
	// if operations for this backup aren't found, or if there are no changes
	// or errors since last update, do nothing
	if !ok || (!operations.ChangesSinceUpdate && len(operations.ErrsSinceUpdate) == 0) {
		return nil
	}
	if err := operations.uploadProgress(backupStore, backupName); err != nil {
		return err
	}
	return nil
}

type OperationsForBackup struct {
	Operations         []*itemoperation.BackupOperation
	ChangesSinceUpdate bool
	ErrsSinceUpdate    []string
}

func (m *OperationsForBackup) DeepCopy() *OperationsForBackup {
	if m == nil {
		return nil
	}
	out := new(OperationsForBackup)
	m.DeepCopyInto(out)
	return out
}

func (m *OperationsForBackup) DeepCopyInto(out *OperationsForBackup) {
	*out = *m
	if m.Operations != nil {
		in, out := &m.Operations, &out.Operations
		*out = make([]*itemoperation.BackupOperation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(itemoperation.BackupOperation)
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

func (m *OperationsForBackup) uploadProgress(backupStore persistence.BackupStore, backupName string) error {
	if len(m.Operations) > 0 {
		var backupItemOperations *bytes.Buffer
		backupItemOperations, errs := encode.ToJSONGzip(m.Operations, "backup item operations list")
		if errs != nil {
			return errors.Wrap(errs[0], "error encoding item operations json")
		}
		err := backupStore.PutBackupItemOperations(backupName, backupItemOperations)
		if err != nil {
			return errors.Wrap(err, "error uploading item operations json")
		}
	}
	m.ChangesSinceUpdate = false
	m.ErrsSinceUpdate = nil
	return nil
}
