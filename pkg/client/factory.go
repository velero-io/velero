/*
Copyright 2017, 2019 the Velero contributors.

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

package client

import (
	"os"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/discovery"
	k8scheme "k8s.io/client-go/kubernetes/scheme"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
)

//go:generate mockery --name Factory

// Factory knows how to create a VeleroClient and Kubernetes client.
type Factory interface {
	// BindFlags binds common flags (--kubeconfig, --namespace) to the passed-in FlagSet.
	BindFlags(flags *pflag.FlagSet)
	// KubeClient returns a Kubernetes client. It uses the following priority to specify the cluster
	// configuration: --kubeconfig flag, KUBECONFIG environment variable, in-cluster configuration.
	KubeClient() (kubernetes.Interface, error)
	// DynamicClient returns a Kubernetes dynamic client. It uses the following priority to specify the cluster
	// configuration: --kubeconfig flag, KUBECONFIG environment variable, in-cluster configuration.
	DynamicClient() (dynamic.Interface, error)
	// KubebuilderClient returns a client for the controller runtime framework. It adds Kubernetes and Velero
	// types to its scheme. It uses the following priority to specify the cluster
	// configuration: --kubeconfig flag, KUBECONFIG environment variable, in-cluster configuration.
	KubebuilderClient() (kbclient.Client, error)
	// KubebuilderWatchClient returns a client with watcher for the controller runtime framework.
	// It adds Kubernetes and Velero types to its scheme. It uses the following priority to specify the cluster
	// configuration: --kubeconfig flag, KUBECONFIG environment variable, in-cluster configuration.
	KubebuilderWatchClient() (kbclient.WithWatch, error)
	// DiscoveryClient returns a Kubernetes discovery client. It uses the following priority to specify the cluster
	// configuration: --kubeconfig flag, KUBECONFIG environment variable, in-cluster configuration.
	DiscoveryClient() (discovery.AggregatedDiscoveryInterface, error)
	// SetBasename changes the basename for an already-constructed client.
	// This is useful for generating clients that require a different user-agent string below the root `velero`
	// command, such as the server subcommand.
	SetBasename(string)
	// SetClientQPS sets the Queries Per Second for a client.
	SetClientQPS(float32)
	// SetClientBurst sets the Burst for a client.
	SetClientBurst(int)
	// ClientConfig returns a rest.Config struct used for client-go clients.
	ClientConfig() (*rest.Config, error)
	// Namespace returns the namespace which the Factory will create clients for.
	Namespace() string
}

type factory struct {
	flags       *pflag.FlagSet
	kubeconfig  string
	kubecontext string
	baseName    string
	namespace   string
	clientQPS   float32
	clientBurst int
}

// NewFactory returns a Factory.
func NewFactory(baseName string, config VeleroConfig) Factory {
	f := &factory{
		flags:    pflag.NewFlagSet("", pflag.ContinueOnError),
		baseName: baseName,
	}

	f.namespace = os.Getenv("VELERO_NAMESPACE")
	if config.Namespace() != "" {
		f.namespace = config.Namespace()
	}

	// We didn't get the namespace via env var or config file, so use the default.
	// Command line flags will override when BindFlags is called.
	if f.namespace == "" {
		f.namespace = velerov1api.DefaultNamespace
	}

	f.flags.StringVar(&f.kubeconfig, "kubeconfig", "", "Path to the kubeconfig file to use to talk to the Kubernetes apiserver. If unset, try the environment variable KUBECONFIG, as well as in-cluster configuration")
	f.flags.StringVarP(&f.namespace, "namespace", "n", f.namespace, "The namespace in which Velero should operate")
	f.flags.StringVar(&f.kubecontext, "kubecontext", "", "The context to use to talk to the Kubernetes apiserver. If unset defaults to whatever your current-context is (kubectl config current-context)")
	return f
}

func (f *factory) BindFlags(flags *pflag.FlagSet) {
	flags.AddFlagSet(f.flags)
}

func (f *factory) ClientConfig() (*rest.Config, error) {
	return Config(f.kubeconfig, f.kubecontext, f.baseName, f.clientQPS, f.clientBurst)
}

func (f *factory) KubeClient() (kubernetes.Interface, error) {
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(clientConfig)

	if err != nil {
		return nil, errors.WithStack(err)
	}
	return kubeClient, nil
}

func (f *factory) DynamicClient() (dynamic.Interface, error) {
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(clientConfig)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return dynamicClient, nil
}

func (f *factory) KubebuilderClient() (kbclient.Client, error) {
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := velerov1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := velerov2alpha1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := k8scheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := snapshotv1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := volumegroupsnapshotv1beta2.AddToScheme(scheme); err != nil {
		return nil, err
	}
	kubebuilderClient, err := kbclient.New(clientConfig, kbclient.Options{
		Scheme: scheme,
	})

	if err != nil {
		return nil, err
	}

	return kubebuilderClient, nil
}

func (f *factory) KubebuilderWatchClient() (kbclient.WithWatch, error) {
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := velerov1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := velerov2alpha1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := k8scheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := snapshotv1api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := volumegroupsnapshotv1beta2.AddToScheme(scheme); err != nil {
		return nil, err
	}
	kubebuilderWatchClient, err := kbclient.NewWithWatch(clientConfig, kbclient.Options{
		Scheme: scheme,
	})

	if err != nil {
		return nil, err
	}

	return kubebuilderWatchClient, nil
}

func (f *factory) DiscoveryClient() (discovery.AggregatedDiscoveryInterface, error) {
	clientConfig, err := f.ClientConfig()
	if err != nil {
		return nil, err
	}
	return discovery.NewDiscoveryClientForConfig(clientConfig)
}

func (f *factory) SetBasename(name string) {
	f.baseName = name
}

func (f *factory) SetClientQPS(qps float32) {
	f.clientQPS = qps
}

func (f *factory) SetClientBurst(burst int) {
	f.clientBurst = burst
}

func (f *factory) Namespace() string {
	return f.namespace
}
