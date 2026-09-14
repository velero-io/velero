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

var CSIDataMoverVolumeInfoTest func() = TestFunc(&CSIDataMoverVolumeInfo{
	BackupVolumeInfo{
		SnapshotMoveData: true,
		SnapshotVolumes:  true,
		TestCase: TestCase{
			CaseBaseName: "csi-data-mover-volumeinfo",
			TestMsg: &TestMSG{
				Desc: "Test backup's VolumeInfo metadata content for CSI data mover case.",
				Text: "The VolumeInfo should be generated, and the SnapshotDataMovementInfo structure should not be nil.",
			},
		},
	},
})

type CSIDataMoverVolumeInfo struct {
	BackupVolumeInfo
}

func (c *CSIDataMoverVolumeInfo) Verify() error {
	volumeInfo, err := GetVolumeInfo(
		c.VeleroCfg.ObjectStoreProvider,
		c.VeleroCfg.CloudCredentialsFile,
		c.VeleroCfg.BSLBucket,
		c.VeleroCfg.BSLPrefix,
		c.VeleroCfg.BSLConfig,
		c.BackupName,
		BackupObjectsPrefix+"/"+c.BackupName,
	)

	Expect(err).ToNot(HaveOccurred(), "Fail to get VolumeInfo metadata in the Backup Repository.")

	fmt.Printf("The VolumeInfo metadata content: %+v\n", *volumeInfo[0])
	Expect(volumeInfo).ToNot(BeEmpty())
	Expect(volumeInfo[0].SnapshotDataMovementInfo).NotTo(BeNil())

	return nil
}
