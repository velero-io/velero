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

package volume

import (
	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// UpdateVolumeSnapshotLocationWithCredentialConfig adds the credentials file path to the config
// if the VSL specifies a credential
func UpdateVolumeSnapshotLocationWithCredentialConfig(location *velerov1api.VolumeSnapshotLocation, credentialStore credentials.FileStore) error {
	if location.Spec.Config == nil {
		location.Spec.Config = make(map[string]string)
	}
	// If the VSL specifies a credential, fetch its path on disk and pass to
	// plugin via the config.
	if location.Spec.Credential != nil && credentialStore != nil {
		credsFile, err := credentialStore.Path(location.Spec.Credential)
		if err != nil {
			return errors.Wrap(err, "unable to get credentials")
		}

		location.Spec.Config["credentialsFile"] = credsFile
	}
	return nil
}
