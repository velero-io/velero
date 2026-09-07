/*
Copyright 2020 the Velero contributors.

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

package serverstatus

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	veleroclient "github.com/vmware-tanzu/velero/pkg/client"
)

type Getter interface {
	GetServerStatus(kbClient kbclient.Client) (*velerov1api.ServerStatusRequest, error)
}

type DefaultServerStatusGetter struct {
	Namespace string
	Context   context.Context
}

func (g *DefaultServerStatusGetter) GetServerStatus(kbClient kbclient.Client) (*velerov1api.ServerStatusRequest, error) {
	created := builder.ForServerStatusRequest(g.Namespace, "", "0").ObjectMeta(builder.WithGenerateName("velero-cli-")).Result()

	if err := veleroclient.CreateRetryGenerateName(kbClient, context.Background(), created); err != nil {
		return nil, errors.WithStack(err)
	}

	key := kbclient.ObjectKey{Name: created.Name, Namespace: g.Namespace}
	err := wait.PollUntilContextCancel(g.Context, 250*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		updated := &velerov1api.ServerStatusRequest{}
		if err := kbClient.Get(ctx, key, updated); err != nil {
			return false, kbclient.IgnoreNotFound(err)
		}

		if updated.Status.Phase == velerov1api.ServerStatusRequestPhaseProcessed {
			created = updated
			return true, nil
		}

		return false, nil
	})

	return created, err
}
