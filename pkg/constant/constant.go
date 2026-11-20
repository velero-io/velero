package constant

const (
	ControllerBackupQueue           = "backup-queue"
	ControllerBackup                = "backup"
	ControllerBackupOperations      = "backup-operations"
	ControllerBackupDeletion        = "backup-deletion"
	ControllerBackupFinalizer       = "backup-finalizer"
	ControllerBackupRepo            = "backup-repo"
	ControllerBackupStorageLocation = "backup-storage-location"
	ControllerBackupSync            = "backup-sync"
	ControllerDataDownload          = "data-download"
	ControllerDataUpload            = "data-upload"
	ControllerDownloadRequest       = "download-request"
	ControllerGarbageCollection     = "gc"
	ControllerPodVolumeBackup       = "pod-volume-backup"
	ControllerRetainedSnapshot      = "retained-snapshot"
	ControllerPodVolumeRestore      = "pod-volume-restore"
	ControllerRestore               = "restore"
	ControllerRestoreOperations     = "restore-operations"
	ControllerSchedule              = "schedule"
	ControllerServerStatusRequest   = "server-status-request"
	ControllerRestoreFinalizer      = "restore-finalizer"

	PluginCSIPVCRestoreRIA            = "velero.io/csi-pvc-restorer"
	PluginCsiVolumeSnapshotRestoreRIA = "velero.io/csi-volumesnapshot-restorer"

	DefaultEphemeralStorageRequest = "0"
	DefaultEphemeralStorageLimit   = "0"
)
