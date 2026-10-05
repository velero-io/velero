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

package podvolume

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
)

// BackupperFactory can construct pod volumes backuppers.
type BackupperFactory interface {
	// NewBackupper returns a pod volumes backupper for use during a single Velero backup.
	NewBackupper(context.Context, logrus.FieldLogger, *velerov1api.Backup, string) (Backupper, error)
}

func NewBackupperFactory(
	repoLocker *repository.RepoLocker,
	repoEnsurer *repository.Ensurer,
	crClient ctrlclient.Client,
	pvbInformer ctrlcache.Informer,
	log logrus.FieldLogger,
) BackupperFactory {
	return &backupperFactory{
		repoLocker:  repoLocker,
		repoEnsurer: repoEnsurer,
		crClient:    crClient,
		pvbInformer: pvbInformer,
		log:         log,
	}
}

type backupperFactory struct {
	repoLocker  *repository.RepoLocker
	repoEnsurer *repository.Ensurer
	crClient    ctrlclient.Client
	pvbInformer ctrlcache.Informer
	log         logrus.FieldLogger
}

func (bf *backupperFactory) NewBackupper(ctx context.Context, log logrus.FieldLogger, backup *velerov1api.Backup, uploaderType string) (Backupper, error) {
	b := newBackupper(ctx, log, bf.repoLocker, bf.repoEnsurer, bf.pvbInformer, bf.crClient, uploaderType, backup)

	if !cache.WaitForCacheSync(ctx.Done(), bf.pvbInformer.HasSynced) {
		return nil, errors.New("timed out waiting for caches to sync")
	}

	return b, nil
}
