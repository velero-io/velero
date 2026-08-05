/*
Copyright The Velero Contributors.

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

package csi

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/util"
)

// CBTInfo define the info for CBT
type CBTInfo struct {
	ChangeID   string
	VolumeID   string
	SnapshotID string
}

// GetCBTInfo returns the CBT info for a snapshot
func GetCBTInfo(ctx context.Context, kubeClient kubernetes.Interface, log logrus.FieldLogger, vs *snapshotv1api.VolumeSnapshot, vsc *snapshotv1api.VolumeSnapshotContent, sourcePVName string) (CBTInfo, error) {
	cbtInfo := CBTInfo{}
	if vs == nil || vsc == nil {
		return cbtInfo, errors.New("vs or vsc is nil")
	}

	cbtInfo.SnapshotID = vs.Name

	if vs.Annotations != nil &&
		(vs.Annotations[util.VSphereCNSChangeIDAnno] != "" ||
			vs.Annotations[util.VSphereCNSSnapshotAnno] != "") {
		cbtInfo.ChangeID = vs.Annotations[util.VSphereCNSChangeIDAnno]

		splitSnapshotAnno := strings.Split(vs.Annotations[util.VSphereCNSSnapshotAnno], "+")
		if len(splitSnapshotAnno) >= 2 {
			cbtInfo.VolumeID = splitSnapshotAnno[0]
		}
		log.Debugf("volumeID %s and changeID %s are read from VKS annotations.", cbtInfo.VolumeID, cbtInfo.ChangeID)
	} else {
		pv, err := kubeClient.CoreV1().PersistentVolumes().Get(ctx, sourcePVName, metav1.GetOptions{})
		if err != nil {
			return cbtInfo, fmt.Errorf("failed to get pv %s: %w", sourcePVName, err)
		}

		if vsc.Status != nil && vsc.Status.SnapshotHandle != nil {
			cbtInfo.ChangeID = *vsc.Status.SnapshotHandle
		}

		if pv.Spec.CSI != nil && pv.Spec.CSI.VolumeHandle != "" {
			cbtInfo.VolumeID = pv.Spec.CSI.VolumeHandle
		}
		log.Debugf("volumeID %s and changeID %s are read from PV and VS's handles.", cbtInfo.VolumeID, cbtInfo.ChangeID)
	}

	if cbtInfo.VolumeID == "" {
		return cbtInfo, fmt.Errorf("volumeID must not be empty for CBT")
	}

	return cbtInfo, nil
}
