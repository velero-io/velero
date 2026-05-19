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

package cacert

import (
	"context"
	"strings"

	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func GetInsecureSkipTLSVerifyFromBackup(ctx context.Context, client kbclient.Client, namespace string, backup *velerov1api.Backup) (bool, error) {
	return GetInsecureSkipTLSVerifyFromBSL(ctx, client, namespace, backup.Spec.StorageLocation)
}

func GetInsecureSkipTLSVerifyFromRestore(ctx context.Context, client kbclient.Client, namespace string, restore *velerov1api.Restore) (bool, error) {
	backup := &velerov1api.Backup{}
	key := kbclient.ObjectKey{
		Namespace: namespace,
		Name:      restore.Spec.BackupName,
	}

	if err := client.Get(ctx, key, backup); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, errors.Wrapf(err, "error getting backup %s", restore.Spec.BackupName)
	}

	return GetInsecureSkipTLSVerifyFromBackup(ctx, client, namespace, backup)
}

func GetInsecureSkipTLSVerifyFromBSL(ctx context.Context, client kbclient.Client, namespace, bslName string) (bool, error) {
	if bslName == "" {
		return false, nil
	}

	bsl := &velerov1api.BackupStorageLocation{}
	key := kbclient.ObjectKey{
		Namespace: namespace,
		Name:      bslName,
	}

	if err := client.Get(ctx, key, bsl); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, errors.Wrapf(err, "error getting backup storage location %s", bslName)
	}

	if bsl.Spec.Config == nil {
		return false, nil
	}

	return strings.EqualFold(bsl.Spec.Config["insecureSkipTLSVerify"], "true"), nil
}
