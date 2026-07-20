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

package delete

import (
	"errors"
	"io"
	"sort"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/test"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestInvokeDeleteItemActionsRunForCorrectItems(t *testing.T) {
	// Declare test-singleton objects.
	fs := test.NewFakeFileSystem()
	log := logrus.StandardLogger()

	tests := []struct {
		name         string
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		actions      map[*recordResourcesAction][]string // recordResourceActions are the plugins that will capture item ids, the []string values are the ids we'll test against.
	}{
		{
			name:   "single action with no selector runs for all items",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction): {"ns-1/pod-1", "ns-2/pod-2", "pv-1", "pv-2"},
			},
		},
		{
			name:   "single action with a resource selector for namespaced resources runs only for matching resources",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("pods"): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:   "single action with a resource selector for cluster-scoped resources runs only for matching resources",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("persistentvolumes"): {"pv-1", "pv-2"},
			},
		},
		{
			name:   "single action with a namespace selector runs only for resources in that namespace",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1"): {"ns-1/pod-1", "ns-1/pvc-1"},
			},
		},
		{
			name:   "multiple actions, each with a different resource selector using short name, run for matching resources",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("po"): {"ns-1/pod-1", "ns-2/pod-2"},
				new(recordResourcesAction).ForResource("pv"): {"pv-1", "pv-2"},
			},
		},
		{
			name:   "actions with selectors that don't match anything don't run for any resources",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("persistentvolumeclaims"): nil,
				new(recordResourcesAction).ForNamespace("ns-2").ForResource("pods"):                   nil,
			},
		},
		{
			name:   "single action with label selector runs only for those items",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("app", "app1")).Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").ObjectMeta(builder.WithLabels("app", "app1")).Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForLabelSelector("app=app1"): {"ns-1/pod-1", "ns-2/pvc-2"},
			},
		},
		{
			name:   "success if resources dir does not exist",
			backup: builder.ForBackup("velero", "velero").Result(),
			tarball: test.NewTarWriter(t).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("persistentvolumeclaims"): nil,
				new(recordResourcesAction).ForNamespace("ns-2").ForResource("pods"):                   nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// test harness contains the fake API server/discovery client
			h := newHarness(t)
			for _, r := range tc.apiResources {
				h.addResource(t, r)
			}

			// Get the plugins out of the map in order to use them.
			var actions []velero.DeleteItemAction
			for action := range tc.actions {
				actions = append(actions, action)
			}

			c := &Context{
				Backup:          tc.backup,
				BackupReader:    tc.tarball,
				Filesystem:      fs,
				DiscoveryHelper: h.discoveryHelper,
				Actions:         actions,
				Log:             log,
			}

			err := InvokeDeleteActions(c)
			require.NoError(t, err)

			// Compare the plugins against the ids that we wanted.
			for action, want := range tc.actions {
				sort.Strings(want)
				sort.Strings(action.ids)
				assert.Equal(t, want, action.ids)
			}
		})
	}
}

// TODO: unify this with the test harness in pkg/restore/restore_test.go
type harness struct {
	*test.APIServer
	discoveryHelper discovery.Helper
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	apiServer := test.NewAPIServer(t)
	log := logrus.StandardLogger()

	discoveryHelper, err := discovery.NewHelper(apiServer.DiscoveryClient, log)
	require.NoError(t, err)

	return &harness{
		APIServer:       apiServer,
		discoveryHelper: discoveryHelper,
	}
}

// addResource adds an APIResource and it's items to a faked API server for testing.
func (h *harness) addResource(t *testing.T, resource *test.APIResource) {
	t.Helper()

	h.DiscoveryClient.WithAPIResource(resource)
	require.NoError(t, h.discoveryHelper.Refresh())

	for _, item := range resource.Items {
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
		require.NoError(t, err)

		unstructuredObj := &unstructured.Unstructured{Object: obj}
		if resource.Namespaced {
			_, err = h.DynamicClient.Resource(resource.GVR()).Namespace(item.GetNamespace()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		} else {
			_, err = h.DynamicClient.Resource(resource.GVR()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		}
		require.NoError(t, err)
	}
}

// recordResourcesAction is a delete item action that can be configured to run
// for specific resources/namespaces and simply record the items that is
// executed for.
type recordResourcesAction struct {
	selector velero.ResourceSelector
	ids      []string
}

func (a *recordResourcesAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *recordResourcesAction) Execute(input *velero.DeleteItemActionExecuteInput) error {
	metadata, err := meta.Accessor(input.Item)
	if err != nil {
		return err
	}

	a.ids = append(a.ids, kubeutil.NamespaceAndName(metadata))

	return nil
}

func (a *recordResourcesAction) ForResource(resource string) *recordResourcesAction {
	a.selector.IncludedResources = append(a.selector.IncludedResources, resource)
	return a
}

func (a *recordResourcesAction) ForNamespace(namespace string) *recordResourcesAction {
	a.selector.IncludedNamespaces = append(a.selector.IncludedNamespaces, namespace)
	return a
}

func (a *recordResourcesAction) ForLabelSelector(selector string) *recordResourcesAction {
	a.selector.LabelSelector = selector
	return a
}

func TestInvokeDeleteItemActionsWithNoPlugins(t *testing.T) {
	c := &Context{
		Backup: builder.ForBackup("velero", "velero").Result(),
		Log:    logrus.StandardLogger(),
		// No other fields are set on the assumption that if 0 actions are present,
		// the backup tarball and file system being empty will produce no errors.
	}
	err := InvokeDeleteActions(c)
	require.NoError(t, err)
}

// failingAction is a DeleteItemAction that always returns an error from Execute.
// It is used to verify that InvokeDeleteActions surfaces plugin errors instead
// of swallowing them.
type failingAction struct {
	selector velero.ResourceSelector
	err      error
	executed int
}

func (a *failingAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *failingAction) Execute(input *velero.DeleteItemActionExecuteInput) error {
	a.executed++
	return a.err
}

func TestInvokeDeleteActionsReturnsPluginErrors(t *testing.T) {
	fs := test.NewFakeFileSystem()
	log := logrus.StandardLogger()

	tarball := test.NewTarWriter(t).
		AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
		Done()

	action := &failingAction{err: errors.New("could not delete artifact")}

	h := newHarness(t)
	h.addResource(t, test.Pods())

	c := &Context{
		Backup:          builder.ForBackup("velero", "velero").Result(),
		BackupReader:    tarball,
		Filesystem:      fs,
		DiscoveryHelper: h.discoveryHelper,
		Actions:         []velero.DeleteItemAction{action},
		Log:             log,
	}

	err := InvokeDeleteActions(c)

	// The plugin error must be surfaced so the caller can fail the deletion
	// rather than orphaning the artifacts the plugin failed to delete.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not delete artifact")
	// The loop must keep going: the action should run for every matching item,
	// not stop at the first failure.
	assert.Equal(t, 2, action.executed)
}
