package datamover

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/label"
	"github.com/velero-io/velero/pkg/plugin/velero"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
	"github.com/velero-io/velero/pkg/util/csi"
	datamoverutil "github.com/velero-io/velero/pkg/util/datamover"
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
	// Only create a snapshot-info ConfigMap when the DataUpload's owning
	// backup (its velero.io/backup-name label) matches the backup currently
	// being deleted. Two other cases reach this code path and must be
	// skipped, because the resulting CM would be unmatchable and only adds
	// etcd churn:
	//
	//  1. The label is missing. We have no verifiable owner, so a CM created
	//     with the executing backup's label is a guess that deleteMovedSnapshots
	//     cannot rely on.
	//  2. The label names a different backup. Velero does not support
	//     self-protection, so this almost always means the velero namespace
	//     was captured in a backup tarball and the DataUpload CR belongs to
	//     an unrelated backup. Creating a CM labeled with the executing
	//     backup mislabels the snapshot and causes the real owning backup's
	//     deleteMovedSnapshots query to miss it, leaking the Kopia snapshot
	//     in the object store.
	//
	// Both cases warn so misconfigured installs surface in logs.
	owner := du.Labels[velerov1.BackupNameLabel]
	switch {
	case owner == "":
		d.logger.Warnf(
			"DataUpload %q has no %q label, so its owning backup cannot be verified; "+
				"skipping snapshot-info ConfigMap creation because a CM without a verifiable owner "+
				"cannot be matched back to its snapshot at backup deletion time.",
			du.Name, velerov1.BackupNameLabel,
		)
		return nil
	case owner != label.GetValidName(input.Backup.Name):
		d.logger.Warnf(
			"DataUpload %q belongs to backup %q but is being deleted under backup %q; "+
				"this almost always means the velero namespace was included in a backup tarball. "+
				"Velero does not support self-protection — exclude the velero namespace from your schedules. "+
				"Skipping snapshot-info ConfigMap creation to avoid mislabeling.",
			du.Name, owner, input.Backup.Name,
		)
		return nil
	}
	// A nil configmap will not fail the backup deletion. The configmap may already
	// exist from a previous deletion attempt that failed, which must not stop the
	// retry from deleting the retained snapshot.
	if cm := genConfigmap(input.Backup, *du); cm != nil {
		if err := d.client.Create(context.Background(), cm); err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.WithStack(errors.Wrapf(err, "failed to create the configmap for DataUpload %s/%s", du.Namespace, du.Name))
		}
	}
	return d.deleteRetainedSnapshot(context.Background(), du)
}

// deleteRetainedSnapshot deletes the volume snapshot that the DataUpload retained in the
// storage. A VolumeSnapshotContent is rebuilt for the retained snapshot handle with
// DeletionPolicy Delete and then deleted, so that the CSI driver deletes the snapshot.
func (d *DataUploadDeleteAction) deleteRetainedSnapshot(ctx context.Context, du *velerov2alpha1.DataUpload) error {
	retained := du.Status.RetainedSnapshot
	if retained == nil {
		return nil
	}
	if retained.SnapshotHandle == "" || retained.Driver == "" {
		return errors.Errorf("invalid retained snapshot of DataUpload %s/%s, handle %q, driver %q",
			du.Namespace, du.Name, retained.SnapshotHandle, retained.Driver)
	}

	d.logger.Infof("Deleting retained snapshot %s of DataUpload %s/%s", retained.SnapshotHandle, du.Namespace, du.Name)

	vsc := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				velerov1.BackupNameLabel: du.Labels[velerov1.BackupNameLabel],
			},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			Driver: retained.Driver,
			Source: snapshotv1api.VolumeSnapshotContentSource{
				SnapshotHandle: &retained.SnapshotHandle,
			},
		},
	}
	if retained.DeletionSecretName != "" {
		vsc.Annotations = map[string]string{
			csi.VSCDeletionSecretNameAnnotation:      retained.DeletionSecretName,
			csi.VSCDeletionSecretNamespaceAnnotation: retained.DeletionSecretNamespace,
		}
	}

	if err := csi.DeleteSnapshotByTempVSC(ctx, d.client, vsc, d.logger); err != nil {
		return errors.Wrapf(err, "failed to delete retained snapshot %s of DataUpload %s/%s", retained.SnapshotHandle, du.Namespace, du.Name)
	}

	return nil
}

// generate the configmap which is to be created and used as a way to communicate the snapshot info to the backup deletion controller
func genConfigmap(bak *velerov1.Backup, du velerov2alpha1.DataUpload) *corev1api.ConfigMap {
	if !datamoverutil.IsBuiltInDataMover(du.Spec.DataMover) || du.Status.SnapshotID == "" {
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
