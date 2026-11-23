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

package backup

import (
	"context"
	"strings"
	"time"

	. "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/perf/test"
)

type BackupTest struct {
	TestCase
}

func (b *BackupTest) Init() error {
	b.TestCase.Init()
	b.Ctx, b.CtxCancel = context.WithTimeout(context.Background(), 6*time.Hour)
	b.CaseBaseName = "backup"
	b.BackupName = "backup-" + b.CaseBaseName + "-" + b.UUIDgen

	b.NSExcluded = &[]string{"kube-system", "velero", "default", "kube-public", "kube-node-lease"}

	b.BackupArgs = []string{
		"create", "--namespace", VeleroCfg.VeleroNamespace, "backup", b.BackupName,
		"--exclude-namespaces", strings.Join(*b.NSExcluded, ","),
		"--default-volumes-to-fs-backup",
		"--snapshot-volumes=false", "--wait",
	}

	b.TestMsg = &TestMSG{
		Desc:      "Do backup resources for performance test",
		FailedMSG: "Failed to backup resources",
		Text:      "Should backup resources success",
	}
	return nil
}
