package datamover

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	repotypes "github.com/vmware-tanzu/velero/pkg/repository/types"
)

type DataUploadDeleteAction struct {
	logger logrus.FieldLogger
	client client.Client
}

func (d *DataUploadDeleteAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"datauploads.velero.io"},
	}, nil
}

func (d *DataUploadDeleteAction) Execute(input *velero.DeleteItemActionExecuteInput) error {
	d.logger.Infof("Executing DataUploadDeleteAction")
	du := &velerov2alpha1.DataUpload{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), &du); err != nil {
		return errors.WithStack(errors.Wrapf(err, "failed to convert input.Item from unstructured"))
	}
	// Detect DataUploads that do not belong to the backup being deleted.
	// Velero does not support self-protection: the velero namespace should
	// never be captured in a backup tarball. When it is (e.g. an operator
	// schedule covers the velero namespace), the tarball can contain
	// DataUpload CRs belonging to *other* backups. Creating a snapshot-info
	// ConfigMap labeled with the executing backup's name in that case
	// mislabels the snapshot and causes the real owning backup's
	// deleteMovedSnapshots query to miss it, leaking the Kopia snapshot in
	// the object store. Log a warning so misconfigured installs are visible,
	// and skip the snapshot-info ConfigMap creation to avoid mislabeling.
	if owner := du.Labels[velerov1.BackupNameLabel]; owner != "" && owner != label.GetValidName(input.Backup.Name) {
		d.logger.Warnf(
			"DataUpload %q belongs to backup %q but is being deleted under backup %q; "+
				"this almost always means the velero namespace was included in a backup tarball. "+
				"Velero does not support self-protection — exclude the velero namespace from your schedules. "+
				"Skipping snapshot-info ConfigMap creation to avoid mislabeling.",
			du.Name, owner, input.Backup.Name,
		)
		return nil
	}
	cm := genConfigmap(input.Backup, *du)
	if cm == nil {
		// will not fail the backup deletion
		return nil
	}
	err := d.client.Create(context.Background(), cm)
	if err != nil {
		return errors.WithStack(errors.Wrapf(err, "failed to create the configmap for DataUpload %s/%s", du.Namespace, du.Name))
	}
	return nil
}

// generate the configmap which is to be created and used as a way to communicate the snapshot info to the backup deletion controller
func genConfigmap(bak *velerov1.Backup, du velerov2alpha1.DataUpload) *corev1api.ConfigMap {
	if !IsBuiltInUploader(du.Spec.DataMover) || du.Status.SnapshotID == "" {
		return nil
	}
	snapshot := repotypes.SnapshotIdentifier{
		VolumeNamespace:       du.Spec.SourceNamespace,
		BackupStorageLocation: bak.Spec.StorageLocation,
		SnapshotID:            du.Status.SnapshotID,
		RepositoryType:        velerov1.BackupRepositoryTypeKopia,
		UploaderType:          GetUploaderType(du.Spec.DataMover),
		Source:                GetRealSource(du.Spec.SourceNamespace, du.Spec.SourcePVC),
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return nil
	}
	data := make(map[string]string)
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	return &corev1api.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1api.SchemeGroupVersion.String(),
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: bak.Namespace,
			Name:      fmt.Sprintf("%s-info", du.Name),
			Labels: map[string]string{
				velerov1.BackupNameLabel:             bak.Name,
				velerov1.DataUploadSnapshotInfoLabel: "true",
			},
		},
		Data: data,
	}
}

func NewDataUploadDeleteAction(logger logrus.FieldLogger, client client.Client) *DataUploadDeleteAction {
	return &DataUploadDeleteAction{
		logger: logger,
		client: client,
	}
}
