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

package restore

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/perf/test"
	"github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

type RestoreTest struct {
	TestCase
}

func (r *RestoreTest) Init() error {
	r.TestCase.Init()
	r.Ctx, r.CtxCancel = context.WithTimeout(context.Background(), 6*time.Hour)
	r.CaseBaseName = "restore"
	r.RestoreName = "restore-" + r.CaseBaseName + "-" + r.UUIDgen

	r.TestMsg = &TestMSG{
		Desc:      "Do restore resources for performance test",
		FailedMSG: "Failed to restore resources",
		Text:      "Should restore resources success",
	}
	return nil
}

func (r *RestoreTest) clearUpResourcesBeforRestore() error {
	// we need to clear up all resources before do the restore test
	return r.TestCase.Destroy()
}

func (r *RestoreTest) Restore() error {
	// we need to clear up all resources before do the restore test
	err := r.clearUpResourcesBeforRestore()
	if err != nil {
		return errors.Wrapf(err, "failed to clear up resources before do the restore test")
	}
	var backupName string
	if VeleroCfg.BackupForRestore != "" {
		backupName = VeleroCfg.BackupForRestore
	} else {
		// put partial parameters initialization here because we could not get latest backups in init periods for
		// velero may not ready
		var err error
		backupName, err = GetLatestSuccessBackupsFromBSL(r.Ctx, VeleroCfg.VeleroCLI, "default")
		if err != nil {
			return errors.Wrapf(err, "failed to get backup to do the restore test")
		}
	}

	r.BackupName = backupName
	r.RestoreArgs = []string{
		"create", "--namespace", VeleroCfg.VeleroNamespace, "restore", r.RestoreName,
		"--from-backup", r.BackupName, "--wait",
	}

	if !VeleroCfg.DeleteClusterResource {
		joinedNsMapping, err := k8s.GetMappingNamespaces(r.Ctx, r.Client, *r.NSExcluded)
		if err != nil {
			return errors.Wrapf(err, "failed to get mapping namespaces in init")
		}

		r.RestoreArgs = append(r.RestoreArgs, "--namespace-mappings")
		r.RestoreArgs = append(r.RestoreArgs, joinedNsMapping)
	}

	return r.TestCase.Restore()
}
func (r *RestoreTest) Destroy() error {
	return nil
}
