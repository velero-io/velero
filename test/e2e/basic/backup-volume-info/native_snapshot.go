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
	"fmt"

	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

var NativeSnapshotVolumeInfoTest func() = TestFunc(&NativeSnapshotVolumeInfo{
	BackupVolumeInfo{
		SnapshotVolumes: true,
		TestCase: TestCase{
			UseVolumeSnapshots: true,
			CaseBaseName:       "native-snapshot-volumeinfo",
			TestMsg: &TestMSG{
				Desc: "Test backup's VolumeInfo metadata content for native snapshot case.",
				Text: "The VolumeInfo should be generated, and the NativeSnapshotInfo structure should not be nil.",
			},
		},
	},
})

type NativeSnapshotVolumeInfo struct {
	BackupVolumeInfo
}

func (n *NativeSnapshotVolumeInfo) Verify() error {
	volumeInfo, err := GetVolumeInfo(
		n.VeleroCfg.ObjectStoreProvider,
		n.VeleroCfg.CloudCredentialsFile,
		n.VeleroCfg.BSLBucket,
		n.VeleroCfg.BSLPrefix,
		n.VeleroCfg.BSLConfig,
		n.BackupName,
		BackupObjectsPrefix+"/"+n.BackupName,
	)

	Expect(err).ToNot(HaveOccurred(), "Fail to get VolumeInfo metadata in the Backup Repository.")

	fmt.Printf("The VolumeInfo metadata content: %+v\n", *volumeInfo[0])
	Expect(volumeInfo).ToNot(BeEmpty())
	Expect(volumeInfo[0].NativeSnapshotInfo).NotTo(BeNil())

	return nil
}
