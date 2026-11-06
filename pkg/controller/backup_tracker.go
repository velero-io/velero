/*
Copyright 2018 the Velero contributors.

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

package controller

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/velero-io/velero/pkg/metrics"
)

// BackupTracker keeps track of in-progress backups.
type BackupTracker interface {
	// Add informs the tracker that a backup is ReadyToStart.
	AddReadyToStart(ns, name string)
	// Add informs the tracker that a backup is in progress.
	Add(ns, name string)
	// Add informs the tracker that a backup has moved beyond InProgress
	AddPostProcessing(ns, name string)
	// Delete informs the tracker that a backup has reached a terminal state.
	Delete(ns, name string)
	// Contains returns true if backup is InProgress or post-InProgress
	Contains(ns, name string) bool
	// RunningCount returns the number of backups which are ReadyToStart or InProgress
	RunningCount() int
}

type backupTracker struct {
	lock                sync.RWMutex
	readyToStartBackups sets.Set[string]
	inProgressBackups   sets.Set[string]
	postProgressBackups sets.Set[string]
	metrics             *metrics.ServerMetrics
}

// NewBackupTracker returns a new BackupTracker.
func NewBackupTracker() BackupTracker {
	return NewBackupTrackerWithMetrics(nil)
}

// NewBackupTrackerWithMetrics returns a new BackupTracker that keeps the
// backup_active_total metric in step with the backups it is tracking. The
// metrics argument may be nil, in which case no metric is recorded.
func NewBackupTrackerWithMetrics(serverMetrics *metrics.ServerMetrics) BackupTracker {
	return &backupTracker{
		readyToStartBackups: sets.New[string](),
		inProgressBackups:   sets.New[string](),
		postProgressBackups: sets.New[string](),
		metrics:             serverMetrics,
	}
}

// recordRunningCount publishes the current running count. Callers must hold
// the write lock.
func (bt *backupTracker) recordRunningCount() {
	if bt.metrics == nil {
		return
	}
	bt.metrics.SetBackupActiveTotal(int64(bt.inProgressBackups.Len() + bt.readyToStartBackups.Len()))
}

func (bt *backupTracker) AddReadyToStart(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	bt.readyToStartBackups.Insert(backupTrackerKey(ns, name))
	bt.recordRunningCount()
}

func (bt *backupTracker) Add(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Insert(key)
	bt.recordRunningCount()
}

func (bt *backupTracker) AddPostProcessing(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Delete(key)
	bt.postProgressBackups.Insert(key)
	bt.recordRunningCount()
}

func (bt *backupTracker) Delete(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Delete(key)
	bt.postProgressBackups.Delete(key)
	bt.recordRunningCount()
}

// Contains returns true if backup is InProgress or post-InProgress
// ignores ReadyToStart, since this is used to determine whether
// a backup is in progress and thus not able to be deleted now.
func (bt *backupTracker) Contains(ns, name string) bool {
	bt.lock.RLock()
	defer bt.lock.RUnlock()

	key := backupTrackerKey(ns, name)
	return bt.inProgressBackups.Has(key) || bt.postProgressBackups.Has(key)
}

// RunningCount returns the number of backups which are ReadyToStart or InProgress
// used by queue controller to determine whether a new backup can be started.
func (bt *backupTracker) RunningCount() int {
	bt.lock.RLock()
	defer bt.lock.RUnlock()

	return bt.inProgressBackups.Len() + bt.readyToStartBackups.Len()
}

func backupTrackerKey(ns, name string) string {
	return fmt.Sprintf("%s/%s", ns, name)
}
