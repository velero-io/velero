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

package basic

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/k8s"
)

func TestDestroyWaitsForTestNamespace(t *testing.T) {
	const name = "csi-vgs-volumeinfo"
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/metadata.name": name}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Labels: map[string]string{"ns-test": "true"}}},
	)
	client.PrependReactor("delete", "namespaces", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})
	pollStarted := make(chan struct{})
	var once sync.Once
	client.PrependReactor("list", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if !action.(clienttesting.ListAction).GetListRestrictions().Labels.Empty() {
			once.Do(func() { close(pollStarted) })
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	v := BackupVolumeInfo{TestCase: test.TestCase{
		CaseBaseName: name,
		Ctx:          ctx,
		Client:       k8s.TestClient{ClientGo: client},
	}}

	done := make(chan error, 1)
	go func() { done <- v.Destroy() }()

	select {
	case <-pollStarted:
	case <-ctx.Done():
		t.Fatal("Destroy did not start waiting for namespace deletion")
	}
	select {
	case err := <-done:
		t.Fatalf("Destroy returned before the namespace was deleted: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", name); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Destroy failed after namespace deletion: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Destroy did not finish after the test namespace was deleted")
	}
}
