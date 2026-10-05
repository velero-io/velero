/*
Copyright 2018, 2019 the Velero contributors.

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

package repository

import (
	"context"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Ensurer ensures that backup repositories are created and ready.
type Ensurer struct {
	log        logrus.FieldLogger
	repoClient client.Client

	// repoLocksMu synchronizes reads/writes to the repoLocks map itself
	// since maps are not threadsafe.
	repoLocksMu     sync.Mutex
	repoLocks       map[BackupRepositoryKey]*sync.Mutex
	resourceTimeout time.Duration
}

func NewEnsurer(repoClient client.Client, log logrus.FieldLogger, resourceTimeout time.Duration) *Ensurer {
	return &Ensurer{
		log:             log,
		repoClient:      repoClient,
		repoLocks:       make(map[BackupRepositoryKey]*sync.Mutex),
		resourceTimeout: resourceTimeout,
	}
}

func (r *Ensurer) EnsureRepo(ctx context.Context, namespace, volumeNamespace, backupLocation, repositoryType string) (*velerov1api.BackupRepository, error) {
	if volumeNamespace == "" || backupLocation == "" || repositoryType == "" {
		return nil, errors.Errorf("wrong parameters, namespace %q, backup storage location %q, repository type %q", volumeNamespace, backupLocation, repositoryType)
	}

	backupRepoKey := BackupRepositoryKey{volumeNamespace, backupLocation, repositoryType}

	log := r.log.WithField("volumeNamespace", volumeNamespace).WithField("backupLocation", backupLocation).WithField("repositoryType", repositoryType)

	// The BackupRepository is labeled with BackupRepositoryKey.
	// This function searches for an existing BackupRepository by BackupRepositoryKey label.
	// If it doesn't exist, it creates a new one and wait for its readiness.
	//
	// The BackupRepository is also named as BackupRepositoryKey.
	// It creates a BackupRepository with deterministic name
	// so that this function could support multiple thread calling by leveraging API server's optimistic lock mechanism.
	// Therefore, the name must be unique for a BackupRepository.
	// Don't use name to filter/search BackupRepository, since it may be changed in future, use label instead.
	log.Debug("Acquiring lock")

	repoMu := r.repoLock(backupRepoKey)
	repoMu.Lock()
	defer func() {
		repoMu.Unlock()
		log.Debug("Released lock")
	}()

	_, err := GetBackupRepository(ctx, r.repoClient, namespace, backupRepoKey, false)
	if err == nil {
		log.Info("Founding existing repo")
		return r.waitBackupRepository(ctx, namespace, backupRepoKey)
	} else if isBackupRepositoryNotFoundError(err) {
		log.Info("No repository found, creating one")

		// no repo found: create one and wait for it to be ready
		return r.createBackupRepositoryAndWait(ctx, namespace, backupRepoKey)
	} else {
		return nil, errors.WithStack(err)
	}
}

func (r *Ensurer) repoLock(key BackupRepositoryKey) *sync.Mutex {
	r.repoLocksMu.Lock()
	defer r.repoLocksMu.Unlock()

	if r.repoLocks[key] == nil {
		r.repoLocks[key] = new(sync.Mutex)
	}

	return r.repoLocks[key]
}

func (r *Ensurer) createBackupRepositoryAndWait(ctx context.Context, namespace string, backupRepoKey BackupRepositoryKey) (*velerov1api.BackupRepository, error) {
	toCreate := NewBackupRepository(namespace, backupRepoKey)

	if err := r.repoClient.Create(ctx, toCreate, &client.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, errors.Wrap(err, "unable to create backup repository resource")
	}

	return r.waitBackupRepository(ctx, namespace, backupRepoKey)
}

func (r *Ensurer) waitBackupRepository(ctx context.Context, namespace string, backupRepoKey BackupRepositoryKey) (*velerov1api.BackupRepository, error) {
	var repo *velerov1api.BackupRepository
	var checkErr error
	checkFunc := func(ctx context.Context) (bool, error) {
		found, err := GetBackupRepository(ctx, r.repoClient, namespace, backupRepoKey, true)
		if err == nil {
			repo = found
			return true, nil
		} else if isBackupRepositoryNotFoundError(err) || isBackupRepositoryNotProvisionedError(err) {
			checkErr = err
			return false, nil
		} else {
			return false, err
		}
	}

	err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, r.resourceTimeout, true, checkFunc)
	if err != nil {
		if err == context.DeadlineExceeded {
			// if deadline is exceeded, return the error from the last check instead of the wait error
			return nil, errors.Wrap(checkErr, "failed to wait BackupRepository, timeout exceeded")
		}
		// if the error is not deadline exceeded, return the error from the wait
		return nil, errors.Wrap(err, "failed to wait BackupRepository, errored early")
	}

	return repo, nil
}
