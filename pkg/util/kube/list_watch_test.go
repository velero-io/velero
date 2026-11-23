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

package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestInternalLW(t *testing.T) {
	stop := make(chan struct{})
	client := velerotest.NewFakeControllerRuntimeClient(t).(kbclient.WithWatch)
	lw := InternalLW{
		Client:     client,
		Namespace:  "velero",
		ObjectList: new(velerov1api.BackupList),
	}

	restoreInformer := cache.NewSharedInformer(&lw, &velerov1api.BackupList{}, time.Second)
	go restoreInformer.Run(stop)

	time.Sleep(1 * time.Second)
	close(stop)

	backupList := new(velerov1api.BackupList)
	err := client.List(t.Context(), backupList)
	require.NoError(t, err)

	_, err = client.Watch(t.Context(), backupList)
	require.NoError(t, err)
}
