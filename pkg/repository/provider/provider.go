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

package provider

import (
	"context"
	"time"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// RepoParam includes the parameters to manipulate a backup repository
type RepoParam struct {
	BackupLocation *velerov1api.BackupStorageLocation
	BackupRepo     *velerov1api.BackupRepository
	CacheDir       string
}

// Provider defines the methods to manipulate a backup repository
type Provider interface {
	ConfigProvider

	// InitRepo is to initialize a repository from a new storage place
	InitRepo(ctx context.Context, param RepoParam) error

	// ConnectToRepo is to establish the connection to a
	// storage place that a repository is already initialized
	ConnectToRepo(ctx context.Context, param RepoParam) error

	// PrepareRepo is a combination of InitRepo and ConnectToRepo,
	// it may do initializing + connecting, connecting only if the repository
	// is already initialized, or do nothing if the repository is already connected
	PrepareRepo(ctx context.Context, param RepoParam) error

	// BoostRepoConnect is used to re-ensure the local connection to the repo,
	// so that the followed operations could succeed in some environment reset
	// scenarios, for example, pod restart
	BoostRepoConnect(ctx context.Context, param RepoParam) error

	// PruneRepo does a full prune/maintenance of the repository
	PruneRepo(ctx context.Context, param RepoParam) error

	// EnsureUnlockRepo esures to remove any stale file locks in the storage
	EnsureUnlockRepo(ctx context.Context, param RepoParam) error

	// Forget is to delete a snapshot from the repository
	Forget(ctx context.Context, snapshotID string, param RepoParam) error

	// BatchForget is to delete a list of snapshots from the repository
	BatchForget(ctx context.Context, snapshotIDs []string, param RepoParam) []error
}

// ConfigProvider defines the methods to get configurations of a backup repository
type ConfigProvider interface {
	// DefaultMaintenanceFrequency returns the default frequency to run maintenance
	DefaultMaintenanceFrequency() time.Duration

	// ClientSideCacheLimit returns the max cache size required on client side
	ClientSideCacheLimit(repoOption map[string]string) int64
}
