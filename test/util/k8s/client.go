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
	"k8s.io/client-go/kubernetes"
	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/test/pkg/client"
)

// TestClient contains different API clients that are in use throughout
// the e2e tests.

type TestClient struct {
	Kubebuilder kbclient.Client

	// clientGo returns a client-go API client.
	//
	// Deprecated, TODO(2.0): presuming all controllers and resources are converted to the
	// controller runtime framework by v2.0, it is the intent to remove all
	// client-go API clients. Please use the controller runtime to make API calls for tests.
	ClientGo kubernetes.Interface

	// dynamicFactory returns a client-go API client for retrieving dynamic clients
	// for GroupVersionResources and GroupVersionKinds.
	//
	// Deprecated, TODO(2.0): presuming all controllers and resources are converted to the
	// controller runtime framework by v2.0, it is the intent to remove all
	// client-go API clients. Please use the controller runtime to make API calls for tests.
	dynamicFactory client.DynamicFactory

	MetricsClient *metricsclientset.Clientset
}

var (
	err error
)

// NewTestClient returns a set of ready-to-use API clients.
func NewTestClient(kubecontext string) (TestClient, error) {
	return InitTestClient(kubecontext)
}

func InitTestClient(kubecontext string) (TestClient, error) {
	config, err := client.LoadConfig()
	if err != nil {
		return TestClient{}, err
	}

	f := client.NewFactory("e2e", kubecontext, config)

	clientGo, err := f.KubeClient()

	if err != nil {
		return TestClient{}, err
	}

	kb, err := f.KubebuilderClient()
	if err != nil {
		return TestClient{}, err
	}

	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return TestClient{}, err
	}

	factory := client.NewDynamicFactory(dynamicClient)

	metricsClient, err := f.MetricsClient()
	if err != nil {
		return TestClient{}, err
	}
	testClient := TestClient{
		Kubebuilder:    kb,
		ClientGo:       clientGo,
		dynamicFactory: factory,
		MetricsClient:  metricsClient,
	}

	return testClient, nil
}
