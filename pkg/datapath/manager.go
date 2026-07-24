/*
Copyright The Velero Contributors.

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

package datapath

import (
	"context"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var ConcurrentLimitExceed error = errors.New("Concurrent number exceeds")
var VGDPCreator = newGeneralDataPath
var MicroServiceBRWatcherCreator = newMicroServiceBRWatcher

type Manager struct {
	cocurrentNum   int
	trackerLock    sync.Mutex
	tracker        map[string]AsyncBR
	reservations   map[string]bool // Track reserved slots before GetExposed completes
}

// NewManager creates the data path manager to manage concurrent data path instances
func NewManager(cocurrentNum int) *Manager {
	return &Manager{
		cocurrentNum: cocurrentNum,
		tracker:      map[string]AsyncBR{},
		reservations: map[string]bool{},
	}
}

// CreateGenericDataPath creates a new generic data path instance
func (m *Manager) CreateGenericDataPath(jobName string, requestorType string, ctx context.Context, client client.Client, namespace string, callbacks Callbacks, log logrus.FieldLogger) (AsyncBR, error) {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	if len(m.tracker) >= m.cocurrentNum {
		return nil, ConcurrentLimitExceed
	}

	m.tracker[jobName] = VGDPCreator(jobName, requestorType, client, namespace, callbacks, log)

	return m.tracker[jobName], nil
}

// CreateMicroServiceBRWatcher creates a new micro service watcher instance
func (m *Manager) CreateMicroServiceBRWatcher(ctx context.Context, client client.Client, kubeClient kubernetes.Interface, mgr manager.Manager, taskType string,
	taskName string, namespace string, podName string, containerName string, associatedObject string, callbacks Callbacks, resume bool, log logrus.FieldLogger) (AsyncBR, error) {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	if !resume {
		// For resume, we skip the limit check
		// For new tasks, check if we have space (either already reserved or have available slots)
		_, alreadyReserved := m.reservations[taskName]
		if !alreadyReserved {
			if (len(m.tracker) + len(m.reservations)) >= m.cocurrentNum {
				return nil, ConcurrentLimitExceed
			}
		}
	}

	m.tracker[taskName] = MicroServiceBRWatcherCreator(client, kubeClient, mgr, taskType, taskName, namespace, podName, containerName, associatedObject, callbacks, log)

	// Release reservation if it exists (it will be replaced by actual AsyncBR in tracker)
	delete(m.reservations, taskName)

	return m.tracker[taskName], nil
}

// RemoveAsyncBR removes a file system backup/restore data path instance
func (m *Manager) RemoveAsyncBR(jobName string) {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	delete(m.tracker, jobName)
}

// GetAsyncBR returns the file system backup/restore data path instance for the specified job name
func (m *Manager) GetAsyncBR(jobName string) AsyncBR {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	if async, exist := m.tracker[jobName]; exist {
		return async
	} else {
		return nil
	}
}

// CanAcceptNewTask checks if a new task can be accepted based on the concurrent limit.
// This is a lightweight check that doesn't create any resources.
func (m *Manager) CanAcceptNewTask(resume bool) bool {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	if resume {
		return true
	}

	// Count both active tasks and reserved slots
	return (len(m.tracker) + len(m.reservations)) < m.cocurrentNum
}

// ReserveSlot reserves a slot in the tracker before expensive operations (like GetExposed).
// Returns ConcurrentLimitExceed if no slots are available.
// Must be paired with either CompleteReservation or ReleaseReservation.
func (m *Manager) ReserveSlot(taskName string) error {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	// Check if already reserved or in tracker
	if _, exists := m.tracker[taskName]; exists {
		return nil // Already active
	}
	if m.reservations[taskName] {
		return nil // Already reserved
	}

	// Check if we can accept a new reservation
	if (len(m.tracker) + len(m.reservations)) >= m.cocurrentNum {
		return ConcurrentLimitExceed
	}

	m.reservations[taskName] = true
	return nil
}

// CompleteReservation completes a reservation by replacing it with the actual AsyncBR.
// Should be called after successful GetExposed and CreateMicroServiceBRWatcher.
func (m *Manager) CompleteReservation(taskName string) {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	delete(m.reservations, taskName)
}

// ReleaseReservation releases a reserved slot if GetExposed or subsequent operations fail.
func (m *Manager) ReleaseReservation(taskName string) {
	m.trackerLock.Lock()
	defer m.trackerLock.Unlock()

	delete(m.reservations, taskName)
}
