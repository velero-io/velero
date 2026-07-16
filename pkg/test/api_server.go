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

package test

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// APIServer contains in-memory fakes for all of the relevant
// Kubernetes API server clients.
type APIServer struct {
	KubeClient      *kubefake.Clientset
	DynamicClient   *dynamicfake.FakeDynamicClient
	DiscoveryClient *DiscoveryClient
}

// NewAPIServer constructs an APIServer with all of its clients
// initialized.
func NewAPIServer(t *testing.T) *APIServer {
	t.Helper()

	var (
		kubeClient    = kubefake.NewSimpleClientset()
		dynamicClient = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{
				{Group: "", Version: "v1", Resource: "namespaces"}:                                         "NamespacesList",
				{Group: "", Version: "v1", Resource: "pods"}:                                               "PodsList",
				{Group: "", Version: "v1", Resource: "persistentvolumes"}:                                  "PVList",
				{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}:                             "PVCList",
				{Group: "", Version: "v1", Resource: "secrets"}:                                            "SecretsList",
				{Group: "", Version: "v1", Resource: "serviceaccounts"}:                                    "ServiceAccountsList",
				{Group: "apps", Version: "v1", Resource: "deployments"}:                                    "DeploymentsList",
				{Group: "apiextensions.k8s.io", Version: "v1beta1", Resource: "customresourcedefinitions"}: "CRDList",
				{Group: "velero.io", Version: "v1", Resource: "volumesnapshotlocations"}:                   "VSLList",
				{Group: "velero.io", Version: "v1", Resource: "backups"}:                                   "BackupList",
				{Group: "extensions", Version: "v1", Resource: "deployments"}:                              "ExtDeploymentsList",
				{Group: "velero.io", Version: "v1", Resource: "deployments"}:                               "VeleroDeploymentsList",
				{Group: "velero.io", Version: "v2alpha1", Resource: "datauploads"}:                         "DataUploadsList",
				{Group: "mygroup.io", Version: "v1", Resource: "mycustomkinds"}:                            "MyCustomKindList",
				{Group: "mygroup.io", Version: "v1", Resource: "myclustercustomkinds"}:                     "MyClusterCustomKindList",
			})
		discoveryClient = &DiscoveryClient{FakeDiscovery: kubeClient.Discovery().(*discoveryfake.FakeDiscovery)}
	)

	return &APIServer{
		KubeClient:      kubeClient,
		DynamicClient:   dynamicClient,
		DiscoveryClient: discoveryClient,
	}
}
