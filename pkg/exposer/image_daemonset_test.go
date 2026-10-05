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

package exposer

import (
	"context"
	"testing"

	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/velero/pkg/install"
)

// TestInheritedPodInfoAgainstRealDaemonSet guards the exclusion against the node-agent
// daemonset that is actually installed, so that a host path volume added to the daemonset
// later is not silently inherited by the data mover pods.
func TestInheritedPodInfoAgainstRealDaemonSet(t *testing.T) {
	nodeAgent := install.DaemonSet("velero")
	client := fake.NewSimpleClientset(&appsv1api.DaemonSet{
		ObjectMeta: nodeAgent.ObjectMeta,
		Spec:       nodeAgent.Spec,
	})

	hostPathVolumes := func(volumes []corev1api.Volume) []string {
		names := []string{}
		for _, volume := range volumes {
			if volume.HostPath != nil {
				names = append(names, volume.Name)
			}
		}
		return names
	}

	// The installed daemonset must carry host path volumes, otherwise this test is vacuous.
	if len(hostPathVolumes(nodeAgent.Spec.Template.Spec.Volumes)) == 0 {
		t.Fatal("the installed node-agent daemonset is expected to have host path volumes")
	}

	// fs-backup resolves pod volume data through the kubelet pod directory, so it keeps them.
	fsBackupInfo, err := getInheritedPodInfo(context.Background(), client, "velero", "linux", inheritHostPathVolumes)
	if err != nil {
		t.Fatalf("error to get inherited pod info for fs-backup: %v", err)
	}

	if len(hostPathVolumes(fsBackupInfo.volumes)) == 0 {
		t.Error("fs-backup is expected to inherit the host path volumes")
	}

	// The data mover pods access data through PVCs, so they must not get any host path.
	dataMoverInfo, err := getInheritedPodInfo(context.Background(), client, "velero", "linux", excludeHostPathVolumes)
	if err != nil {
		t.Fatalf("error to get inherited pod info for data mover: %v", err)
	}

	if inherited := hostPathVolumes(dataMoverInfo.volumes); len(inherited) > 0 {
		t.Errorf("data mover pods are not expected to inherit host path volumes, but got %v", inherited)
	}

	// The other volumes, e.g., the scratch volume, are still required.
	if len(dataMoverInfo.volumes) == 0 {
		t.Error("data mover pods are expected to inherit the volumes other than the host path ones")
	}

	// Every remaining mount must still have its backing volume.
	volumeNames := map[string]struct{}{}
	for _, volume := range dataMoverInfo.volumes {
		volumeNames[volume.Name] = struct{}{}
	}

	for _, volumeMount := range dataMoverInfo.volumeMounts {
		if _, exist := volumeNames[volumeMount.Name]; !exist {
			t.Errorf("volume mount %q doesn't have a backing volume", volumeMount.Name)
		}
	}
}
