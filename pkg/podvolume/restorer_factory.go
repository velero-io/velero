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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
)

// RestorerFactory can construct pod volumes restorers.
type RestorerFactory interface {
	// NewRestorer returns a pod volumes restorer for use during a single Velero restore.
	NewRestorer(context.Context, *velerov1api.Restore) (Restorer, error)
}

func NewRestorerFactory(repoLocker *repository.RepoLocker,
	repoEnsurer *repository.Ensurer,
	kubeClient kubernetes.Interface,
	crClient ctrlclient.Client,
	pvrInformer ctrlcache.Informer,
	log logrus.FieldLogger) RestorerFactory {
	return &restorerFactory{
		repoLocker:  repoLocker,
		repoEnsurer: repoEnsurer,
		kubeClient:  kubeClient,
		crClient:    crClient,
		pvrInformer: pvrInformer,
		log:         log,
	}
}

type restorerFactory struct {
	repoLocker  *repository.RepoLocker
	repoEnsurer *repository.Ensurer
	kubeClient  kubernetes.Interface
	crClient    ctrlclient.Client
	pvrInformer ctrlcache.Informer
	log         logrus.FieldLogger
}

func (rf *restorerFactory) NewRestorer(ctx context.Context, restore *velerov1api.Restore) (Restorer, error) {
	r := newRestorer(ctx, rf.repoLocker, rf.repoEnsurer, rf.pvrInformer, rf.kubeClient, rf.crClient, restore, rf.log)

	if !cache.WaitForCacheSync(ctx.Done(), rf.pvrInformer.HasSynced) {
		return nil, errors.New("timed out waiting for cache to sync")
	}

	return r, nil
}
