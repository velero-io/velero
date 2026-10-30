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

package inplacerestore

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
)

// FileSystemBackupInplaceRestoreTest covers test plan section 1.15.4.
var FileSystemBackupInplaceRestoreTest = func() {
	for _, policy := range []string{"full", "incremental"} {
		Context(fmt.Sprintf("File system backup, in-place %s restore", policy),
			Label(policy),
			TestFunc(&FilesystemInplaceRestore{
				InplaceRestore: InplaceRestore{dataMover: "velero", policy: policy},
			}),
		)
	}
}

type FilesystemInplaceRestore struct {
	InplaceRestore
}

func (f *FilesystemInplaceRestore) Init() error {
	if err := f.InplaceRestore.Init(); err != nil {
		return err
	}
	f.VeleroCfg.UseVolumeSnapshots = false
	f.TestMsg.Desc = fmt.Sprintf("File system backup, in-place %s restore", f.policy)
	f.BackupArgs = []string{
		"backup", "create", f.BackupName, "--namespace", f.VeleroCfg.VeleroNamespace,
		"--include-namespaces", f.CaseBaseName, "--default-volumes-to-fs-backup=true",
		"--snapshot-volumes=false", "--snapshot-move-data=false", "--wait",
	}
	// Init also sets the in-place policy and delete-extra-files flag for restore.
	return nil
}

func (f *FilesystemInplaceRestore) Start() error {
	if f.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		Skip("These cases use a Linux filesystem workload")
	}
	// File system backup does not require the CSI feature or snapshot support.
	return f.TestCase.Start()
}

func (f *FilesystemInplaceRestore) Destroy() error {
	// Recreate the controller and pod during restore so Velero can inject the
	// filesystem restore init container. Keep the PVC and its underlying volume.
	return f.prepareRestore(true)
}

func (f *FilesystemInplaceRestore) Verify() error {
	if err := f.verifyVolumeData(false); err != nil {
		return err
	}

	By("Verify the PodVolumeRestore completed with the expected restore type and byte counts")
	restores := new(velerov1.PodVolumeRestoreList)
	if err := f.Client.Kubebuilder.List(f.Ctx, restores,
		controllerclient.InNamespace(f.VeleroCfg.VeleroNamespace),
		controllerclient.MatchingLabels{velerov1.RestoreNameLabel: f.RestoreName}); err != nil {
		return err
	}
	Expect(restores.Items).To(HaveLen(1), "Expected one PodVolumeRestore for the workload volume")
	restore := restores.Items[0]
	fmt.Fprintf(GinkgoWriter, "PodVolumeRestore %s: spec=%+v status=%+v\n", restore.Name, restore.Spec, restore.Status)
	Expect(restore.Spec.Pod.Namespace).To(Equal(f.CaseBaseName))
	Expect(restore.Spec.Volume).To(Equal("volume"))
	Expect(strings.ToLower(restore.Spec.RestoreType)).To(Equal(f.policy))
	Expect(restore.Status.Phase).To(Equal(velerov1.PodVolumeRestorePhaseCompleted))
	Expect(restore.Status.FallbackFull).To(BeFalse())
	Expect(restore.Status.IncrementalBytes).NotTo(BeNil())
	Expect(*restore.Status.IncrementalBytes).To(Equal(restore.Status.Progress.TotalBytes))
	Expect(restore.Status.Progress.BytesDone).To(Equal(restore.Status.Progress.TotalBytes))

	if f.policy == "full" {
		Expect(restore.Status.Progress.TotalBytes).To(Equal(128 * miB))
	} else {
		// Only the missing data02 (64MiB) should transfer. The test plan also
		// shows the two bytes of the deleted extra file "a\n" included in totals.
		Expect(restore.Status.Progress.TotalBytes).To(Or(Equal(64*miB), Equal(64*miB+2)))
	}
	return nil
}
