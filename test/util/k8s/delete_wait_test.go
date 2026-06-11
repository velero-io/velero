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

package k8s

import (
	"testing"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
)

func TestWaitForServiceDeletePollsRequestedService(t *testing.T) {
	const namespace = "test-ns"
	const name = "test-service"

	client := fake.NewSimpleClientset(&corev1api.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	})

	if err := WaitForServiceDelete(TestClient{ClientGo: client}, namespace, name, true); err != nil {
		t.Fatalf("WaitForServiceDelete returned error: %v", err)
	}

	assertGetActionName(t, client.Actions(), "services", name)
}

func TestWaitForSecretDeletePollsRequestedSecret(t *testing.T) {
	const namespace = "test-ns"
	const name = "test-secret"

	client := fake.NewSimpleClientset(&corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	})

	if err := WaitForSecretDelete(client, namespace, name); err != nil {
		t.Fatalf("WaitForSecretDelete returned error: %v", err)
	}

	assertGetActionName(t, client.Actions(), "secrets", name)
}

func TestWaitForConfigmapDeletePollsRequestedConfigMap(t *testing.T) {
	const namespace = "test-ns"
	const name = "test-configmap"

	client := fake.NewSimpleClientset(&corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	})

	if err := WaitForConfigmapDelete(client, namespace, name); err != nil {
		t.Fatalf("WaitForConfigmapDelete returned error: %v", err)
	}

	assertGetActionName(t, client.Actions(), "configmaps", name)
}

func assertGetActionName(t *testing.T, actions []kubetesting.Action, resource, expectedName string) {
	t.Helper()

	for _, action := range actions {
		getAction, ok := action.(kubetesting.GetAction)
		if !ok || getAction.GetVerb() != "get" || getAction.GetResource().Resource != resource {
			continue
		}

		if getAction.GetName() != expectedName {
			t.Fatalf("expected get action for %q, got %q", expectedName, getAction.GetName())
		}
		return
	}

	t.Fatalf("expected get action for resource %q", resource)
}
