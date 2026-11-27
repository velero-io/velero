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
	// IsTracked returns true if backup is ReadyToStart, InProgress or post-InProgress
	IsTracked(ns, name string) bool
	// RunningCount returns the number of backups which are ReadyToStart or InProgress
	RunningCount() int
}

type backupTracker struct {
	lock                sync.RWMutex
	readyToStartBackups sets.Set[string]
	inProgressBackups   sets.Set[string]
	postProgressBackups sets.Set[string]
}

// NewBackupTracker returns a new BackupTracker.
func NewBackupTracker() BackupTracker {
	return &backupTracker{
		readyToStartBackups: sets.New[string](),
		inProgressBackups:   sets.New[string](),
		postProgressBackups: sets.New[string](),
	}
}

func (bt *backupTracker) AddReadyToStart(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	bt.readyToStartBackups.Insert(backupTrackerKey(ns, name))
}

func (bt *backupTracker) Add(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Insert(key)
}

func (bt *backupTracker) AddPostProcessing(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Delete(key)
	bt.postProgressBackups.Insert(key)
}

func (bt *backupTracker) Delete(ns, name string) {
	bt.lock.Lock()
	defer bt.lock.Unlock()

	key := backupTrackerKey(ns, name)
	bt.readyToStartBackups.Delete(key)
	bt.inProgressBackups.Delete(key)
	bt.postProgressBackups.Delete(key)
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

// IsTracked returns true if backup is ReadyToStart, InProgress or post-InProgress
// used by queue controller to skip a backup that is already past Queued.
func (bt *backupTracker) IsTracked(ns, name string) bool {
	bt.lock.RLock()
	defer bt.lock.RUnlock()

	key := backupTrackerKey(ns, name)
	return bt.readyToStartBackups.Has(key) || bt.inProgressBackups.Has(key) || bt.postProgressBackups.Has(key)
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
