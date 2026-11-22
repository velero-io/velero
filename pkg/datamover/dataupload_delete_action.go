package datamover

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	"github.com/velero-io/velero/pkg/util"
	"github.com/velero-io/velero/pkg/util/datamover"
	retainedsnapshot "github.com/velero-io/velero/pkg/util/retainedsnapshot"
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
	// Only create ConfigMaps when the DataUpload's owning backup (its
	// velero.io/backup-name label) matches the backup currently being deleted.
	// Two other cases reach this code path and must be skipped, because the
	// resulting CM would be unmatchable and only adds etcd churn:
	//
	//  1. The label is missing. We have no verifiable owner, so a CM created
	//     with the executing backup's label is a guess that the deletion
	//     cannot rely on.
	//  2. The label names a different backup. Velero does not support
	//     self-protection, so this almost always means the velero namespace
	//     was captured in a backup tarball and the DataUpload CR belongs to
	//     an unrelated backup. Creating a CM labeled with the executing
	//     backup mislabels the snapshot and causes the real owning backup's
	//     deletion to miss it, leaking the snapshot in the storage.
	//
	// Both cases warn so misconfigured installs surface in logs.
	owner := du.Labels[velerov1.BackupNameLabel]
	switch {
	case owner == "":
		d.logger.Warnf(
			"DataUpload %q has no %q label, so its owning backup cannot be verified; "+
				"skipping ConfigMap creation because a CM without a verifiable owner "+
				"cannot be matched back to its snapshot at backup deletion time.",
			du.Name, velerov1.BackupNameLabel,
		)
		return nil
	case owner != label.GetValidName(input.Backup.Name):
		d.logger.Warnf(
			"DataUpload %q belongs to backup %q but is being deleted under backup %q; "+
				"this almost always means the velero namespace was included in a backup tarball. "+
				"Velero does not support self-protection — exclude the velero namespace from your schedules. "+
				"Skipping ConfigMap creation to avoid mislabeling.",
			du.Name, owner, input.Backup.Name,
		)
		return nil
	}
	// The snapshot-info ConfigMap of the repository data is only created for
	// a DataUpload the config can be generated for; the retained-snapshot
	// record gather below must not depend on it, or a failed or interrupted
	// DataUpload with a retained record but no SnapshotID would lose its
	// record as soon as the DataUpload is gone from the cluster.
	if cm := genConfigmap(input.Backup, *du); cm != nil {
		err := d.client.Create(context.Background(), cm)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.WithStack(errors.Wrapf(err, "failed to create the configmap for DataUpload %s/%s", du.Namespace, du.Name))
		}
	}

	// The DataUploads are deleted in an earlier step of the backup deletion
	// than the retained snapshots, so the working record of a retained
	// snapshot is gathered here, from the backup tarball, into the sharded
	// ConfigMap family the retained-snapshot controller is keyed by. A
	// surviving record means the snapshot was not released, whatever the
	// DataUpload's final phase, and even a stale record is harmless, because
	// a deletion that finds the snapshot already gone is a success. The
	// family is written create-or-update, so a retry of the backup deletion
	// merges into the map an earlier, failed attempt left behind.
	entries := map[string]*retainedsnapshot.Entry{}
	if entry := retainedsnapshot.FromDataUploadStatus(du); entry != nil {
		// A record read from the tarball is not trusted, whatever it was on
		// the live DataUpload: the tarball is backup-storage data, written by
		// anyone who can write the storage, so only a live DataUpload read --
		// the backup-deletion controller's own gather -- establishes trust.
		// An untrusted record naming a driver the cluster does not run is
		// moved to the orphan-snapshot ConfigMap instead of timing out
		// against a temp content the driver will never delete.
		entry.Trusted = false
		entries[du.Name] = entry
	} else if entry := d.unrecordedRetainedSnapshotEntry(input.Backup, *du); entry != nil {
		// A backup taken before Velero recorded retained snapshots kept its
		// snapshot through a Retain VolumeSnapshotClass; its DataUpload
		// carries no record, but the block uploader saved the handle as the
		// cbt-change-id tag of the repository snapshot, and the
		// backup-deletion controller resolves it from there before the
		// repository data is deleted.
		entries[du.Name] = entry
	}
	if err := retainedsnapshot.WriteEntries(context.Background(), d.client, input.Backup, entries); err != nil {
		return errors.WithStack(errors.Wrapf(err, "failed to gather the retained snapshot record of DataUpload %s/%s", du.Namespace, du.Name))
	}
	return nil
}

// unrecordedRetainedSnapshotEntry builds the pending entry of a DataUpload of
// a backup taken before Velero recorded retained snapshots. The handle is not
// known yet: the entry identifies the repository snapshot, and the
// backup-deletion controller resolves the handle from its cbt-change-id tag
// before the repository data is deleted. The VolumeSnapshotClass is looked up
// in the cluster where the deletion runs, and the deletion secret is taken
// from the class parameters; a backup whose class was never synced to that
// cluster, or whose class names the deletion secret with a template, is left
// for manual cleanup. The vSphere CSI driver is excluded because its change
// ID is not a snapshot handle.
func (d *DataUploadDeleteAction) unrecordedRetainedSnapshotEntry(bak *velerov1.Backup, du velerov2alpha1.DataUpload) *retainedsnapshot.Entry {
	if du.Spec.SnapshotType != velerov2alpha1.SnapshotTypeCSI || du.Spec.CSISnapshot == nil ||
		!datamover.IsVeleroBlockDataMover(du.Spec.DataMover) ||
		du.Status.Phase != velerov2alpha1.DataUploadPhaseCompleted || du.Status.SnapshotID == "" {
		return nil
	}

	log := d.logger.WithField("dataupload", du.Namespace+"/"+du.Name)
	driver := du.Spec.CSISnapshot.Driver
	if driver == "" || driver == util.VSphereCSIDriverName {
		// The vSphere change ID is not the snapshot handle.
		return nil
	}
	if du.Spec.CSISnapshot.SnapshotClass == "" {
		return nil
	}

	// The backup kept the snapshot if the VolumeSnapshotClass has deletionPolicy Retain.
	class := &snapshotv1api.VolumeSnapshotClass{}
	if err := d.client.Get(context.Background(), client.ObjectKey{Name: du.Spec.CSISnapshot.SnapshotClass}, class); err != nil {
		log.WithError(err).Warnf("Failed to get VolumeSnapshotClass %s, a snapshot it retained needs manual cleanup", du.Spec.CSISnapshot.SnapshotClass)
		return nil
	}
	if class.DeletionPolicy != snapshotv1api.VolumeSnapshotContentRetain {
		return nil
	}

	entry := &retainedsnapshot.Entry{
		Driver: driver,
		Snapshot: &repotypes.SnapshotIdentifier{
			VolumeNamespace:       du.Spec.SourceNamespace,
			BackupStorageLocation: bak.Spec.StorageLocation,
			SnapshotID:            du.Status.SnapshotID,
			RepositoryType:        velerov1.BackupRepositoryTypeKopia,
			UploaderType:          GetUploaderType(du.Spec.DataMover),
			Source:                GetRealSource(du.Spec.SourceNamespace, du.Spec.SourcePVC),
		},
	}
	if name := class.Parameters[velerov1.PrefixedSecretNameAnnotation]; name != "" {
		// A templated secret name or namespace cannot be resolved to the
		// secret the driver needs: the temp VolumeSnapshotContent would be
		// built without credentials, and the driver's credential failures
		// never qualify for escalation, so the backup would be undeletable.
		// The entry is left out and the snapshot is flagged for manual
		// cleanup, the same as a class that no longer exists.
		if isTemplateSecret(name) {
			log.Warnf("VolumeSnapshotClass %s names the deletion secret with a template, a snapshot it retained needs manual cleanup", class.Name)
			return nil
		}
		entry.DeletionSecretRef = &corev1api.SecretReference{
			Name:      name,
			Namespace: class.Parameters[velerov1.PrefixedSecretNamespaceAnnotation],
		}
		if isTemplateSecret(entry.DeletionSecretRef.Namespace) {
			log.Warnf("VolumeSnapshotClass %s names the deletion secret with a template, a snapshot it retained needs manual cleanup", class.Name)
			return nil
		}
	}

	log.Infof("DataUpload has no retained snapshot record, the handle is read from repository snapshot %s", du.Status.SnapshotID)
	return entry
}

func isTemplateSecret(value string) bool {
	return strings.Contains(value, "${")
}

// generate the configmap which is to be created and used as a way to communicate the snapshot info to the backup deletion controller
func genConfigmap(bak *velerov1.Backup, du velerov2alpha1.DataUpload) *corev1api.ConfigMap {
	if !datamover.IsBuiltInDataMover(du.Spec.DataMover) || du.Status.SnapshotID == "" {
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
