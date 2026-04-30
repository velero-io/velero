/*
Copyright the Velero Contributors.

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
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	corev1api "k8s.io/api/core/v1"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"

	"github.com/vmware-tanzu/velero/internal/hook"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
	"github.com/vmware-tanzu/velero/pkg/podexec"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// BackupVersion is the current backup major version for Velero.
// Deprecated, use BackupFormatVersion
const BackupVersion = 1

// BackupFormatVersion is the current backup version for Velero, including major, minor, and patch.
const BackupFormatVersion = "1.1.0"

// ArgoCD managed by namespace label key
const ArgoCDManagedByNamespaceLabel = "argocd.argoproj.io/managed-by"

// Backupper performs backups.
type Backupper interface {
	// Backup takes a backup using the specification in the velerov1api.Backup and writes backup and log data
	// to the given writers.
	Backup(logger logrus.FieldLogger, backup *Request, backupFile io.Writer, actions []biav2.BackupItemAction, volumeSnapshotterGetter VolumeSnapshotterGetter) error
	BackupWithResolvers(log logrus.FieldLogger, backupRequest *Request, backupFile io.Writer, backupItemActionResolver framework.BackupItemActionResolverV2, volumeSnapshotterGetter VolumeSnapshotterGetter) error
	FinalizeBackup(log logrus.FieldLogger, backupRequest *Request, inBackupFile io.Reader, outBackupFile io.Writer,
		backupItemActionResolver framework.BackupItemActionResolverV2,
		asyncBIAOperations []*itemoperation.BackupOperation) error
}

// kubernetesBackupper implements Backupper.
type kubernetesBackupper struct {
	kbClient                  kbclient.Client
	dynamicFactory            client.DynamicFactory
	discoveryHelper           discovery.Helper
	podCommandExecutor        podexec.PodCommandExecutor
	podVolumeBackupperFactory podvolume.BackupperFactory
	podVolumeTimeout          time.Duration
	defaultVolumesToFsBackup  bool
	clientPageSize            int
	uploaderType              string
}

func (i *itemKey) String() string {
	return fmt.Sprintf("resource=%s,namespace=%s,name=%s", i.resource, i.namespace, i.name)
}

func cohabitatingResources() map[string]*cohabitatingResource {
	return map[string]*cohabitatingResource{
		"deployments":     newCohabitatingResource("deployments", "extensions", "apps"),
		"daemonsets":      newCohabitatingResource("daemonsets", "extensions", "apps"),
		"replicasets":     newCohabitatingResource("replicasets", "extensions", "apps"),
		"networkpolicies": newCohabitatingResource("networkpolicies", "extensions", "networking.k8s.io"),
		"events":          newCohabitatingResource("events", "", "events.k8s.io"),
	}
}

// NewKubernetesBackupper creates a new kubernetesBackupper.
func NewKubernetesBackupper(
	kbClient kbclient.Client,
	discoveryHelper discovery.Helper,
	dynamicFactory client.DynamicFactory,
	podCommandExecutor podexec.PodCommandExecutor,
	podVolumeBackupperFactory podvolume.BackupperFactory,
	podVolumeTimeout time.Duration,
	defaultVolumesToFsBackup bool,
	clientPageSize int,
	uploaderType string,
) (Backupper, error) {
	return &kubernetesBackupper{
		kbClient:                  kbClient,
		discoveryHelper:           discoveryHelper,
		dynamicFactory:            dynamicFactory,
		podCommandExecutor:        podCommandExecutor,
		podVolumeBackupperFactory: podVolumeBackupperFactory,
		podVolumeTimeout:          podVolumeTimeout,
		defaultVolumesToFsBackup:  defaultVolumesToFsBackup,
		clientPageSize:            clientPageSize,
		uploaderType:              uploaderType,
	}, nil
}

// getNamespaceIncludesExcludes returns an IncludesExcludes list containing which namespaces to
// include and exclude from the backup.
func getNamespaceIncludesExcludes(backup *velerov1api.Backup) *collections.IncludesExcludes {
	return collections.NewIncludesExcludes().Includes(backup.Spec.IncludedNamespaces...).Excludes(backup.Spec.ExcludedNamespaces...)
}

func getResourceHooks(hookSpecs []velerov1api.BackupResourceHookSpec, discoveryHelper discovery.Helper) ([]hook.ResourceHook, error) {
	resourceHooks := make([]hook.ResourceHook, 0, len(hookSpecs))

	for _, s := range hookSpecs {
		h, err := getResourceHook(s, discoveryHelper)
		if err != nil {
			return []hook.ResourceHook{}, err
		}

		resourceHooks = append(resourceHooks, h)
	}

	return resourceHooks, nil
}

func getResourceHook(hookSpec velerov1api.BackupResourceHookSpec, discoveryHelper discovery.Helper) (hook.ResourceHook, error) {
	h := hook.ResourceHook{
		Name: hookSpec.Name,
		Selector: hook.ResourceHookSelector{
			Namespaces: collections.NewIncludesExcludes().Includes(hookSpec.IncludedNamespaces...).Excludes(hookSpec.ExcludedNamespaces...),
			Resources:  collections.GetResourceIncludesExcludes(discoveryHelper, hookSpec.IncludedResources, hookSpec.ExcludedResources),
		},
		Pre:  hookSpec.PreHooks,
		Post: hookSpec.PostHooks,
	}

	if hookSpec.LabelSelector != nil {
		labelSelector, err := metav1.LabelSelectorAsSelector(hookSpec.LabelSelector)
		if err != nil {
			return hook.ResourceHook{}, errors.WithStack(err)
		}
		h.Selector.LabelSelector = labelSelector
	}

	return h, nil
}

type VolumeSnapshotterGetter interface {
	GetVolumeSnapshotter(name string) (vsv1.VolumeSnapshotter, error)
}

// Backup backs up the items specified in the Backup, placing them in a gzip-compressed tar file
// written to backupFile. The finalized velerov1api.Backup is written to metadata. Any error that represents
// a complete backup failure is returned. Errors that constitute partial failures (i.e. failures to
// back up individual resources that don't prevent the backup from continuing to be processed) are logged
// to the backup log.
func (kb *kubernetesBackupper) Backup(log logrus.FieldLogger, backupRequest *Request, backupFile io.Writer,
	actions []biav2.BackupItemAction, volumeSnapshotterGetter VolumeSnapshotterGetter) error {
	backupItemActions := framework.NewBackupItemActionResolverV2(actions)
	return kb.BackupWithResolvers(log, backupRequest, backupFile, backupItemActions, volumeSnapshotterGetter)
}

func (kb *kubernetesBackupper) BackupWithResolvers(log logrus.FieldLogger,
	backupRequest *Request,
	backupFile io.Writer,
	backupItemActionResolver framework.BackupItemActionResolverV2,
	volumeSnapshotterGetter VolumeSnapshotterGetter) error {
	gzippedData := gzip.NewWriter(backupFile)
	defer gzippedData.Close()

	tw := tar.NewWriter(gzippedData)
	defer tw.Close()

	log.Info("Writing backup version file")
	if err := kb.writeBackupVersion(tw); err != nil {
		return errors.WithStack(err)
	}

	backupRequest.NamespaceIncludesExcludes = getNamespaceIncludesExcludes(backupRequest.Backup)
	log.Infof("Including namespaces: %s", backupRequest.NamespaceIncludesExcludes.IncludesString())
	log.Infof("Excluding namespaces: %s", backupRequest.NamespaceIncludesExcludes.ExcludesString())

	// check if there are any namespaces included in the backup which are managed by argoCD
	// We will check for the existence of a ArgoCD label in the includedNamespaces and add a warning
	// so that users are at least aware about the existence of argoCD managed ns in their backup
	if len(backupRequest.Spec.IncludedNamespaces) > 0 {
		nsManagedByArgoCD := getNamespacesManagedByArgoCD(kb.kbClient, backupRequest.Spec.IncludedNamespaces, log)

		if len(nsManagedByArgoCD) > 0 {
			log.Warnf("backup operation may encounter complications and potentially produce undesirable results due to the inclusion of namespaces %v managed by ArgoCD in the backup.", nsManagedByArgoCD)
		}
	}

	if collections.UseOldResourceFilters(backupRequest.Spec) {
		backupRequest.ResourceIncludesExcludes = collections.GetGlobalResourceIncludesExcludes(kb.discoveryHelper, log,
			backupRequest.Spec.IncludedResources,
			backupRequest.Spec.ExcludedResources,
			backupRequest.Spec.IncludeClusterResources,
			*backupRequest.NamespaceIncludesExcludes)
	} else {
		backupRequest.ResourceIncludesExcludes = collections.GetScopeResourceIncludesExcludes(kb.discoveryHelper, log,
			backupRequest.Spec.IncludedNamespaceScopedResources,
			backupRequest.Spec.ExcludedNamespaceScopedResources,
			backupRequest.Spec.IncludedClusterScopedResources,
			backupRequest.Spec.ExcludedClusterScopedResources,
			*backupRequest.NamespaceIncludesExcludes,
		)
	}

	log.Infof("Backing up all volumes using pod volume backup: %t", boolptr.IsSetToTrue(backupRequest.Spec.DefaultVolumesToFsBackup))

	var err error
	backupRequest.ResourceHooks, err = getResourceHooks(backupRequest.Spec.Hooks.Resources, kb.discoveryHelper)
	if err != nil {
		log.WithError(errors.WithStack(err)).Debugf("Error from getResourceHooks")
		return err
	}

	backupRequest.ResolvedActions, err = backupItemActionResolver.ResolveActions(kb.discoveryHelper, log)
	if err != nil {
		log.WithError(errors.WithStack(err)).Debugf("Error from backupItemActionResolver.ResolveActions")
		return err
	}

	backupRequest.BackedUpItems = map[itemKey]struct{}{}

	podVolumeTimeout := kb.podVolumeTimeout
	if val := backupRequest.Annotations[velerov1api.PodVolumeOperationTimeoutAnnotation]; val != "" {
		parsed, err := time.ParseDuration(val)
		if err != nil {
			log.WithError(errors.WithStack(err)).Errorf("Unable to parse pod volume timeout annotation %s, using server value.", val)
		} else {
			podVolumeTimeout = parsed
		}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), podVolumeTimeout)
	defer cancelFunc()

	var podVolumeBackupper podvolume.Backupper
	if kb.podVolumeBackupperFactory != nil {
		podVolumeBackupper, err = kb.podVolumeBackupperFactory.NewBackupper(ctx, backupRequest.Backup, kb.uploaderType)
		if err != nil {
			log.WithError(errors.WithStack(err)).Debugf("Error from NewBackupper")
			return errors.WithStack(err)
		}
	}

	// set up a temp dir for the itemCollector to use to temporarily
	// store items as they're scraped from the API.
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		return errors.Wrap(err, "error creating temp dir for backup")
	}
	defer os.RemoveAll(tempDir)

	collector := &itemCollector{
		log:                   log,
		backupRequest:         backupRequest,
		discoveryHelper:       kb.discoveryHelper,
		dynamicFactory:        kb.dynamicFactory,
		cohabitatingResources: cohabitatingResources(),
		dir:                   tempDir,
		pageSize:              kb.clientPageSize,
	}

	items := collector.getAllItems()
	log.WithField("progress", "").Infof("Collected %d items matching the backup spec from the Kubernetes API (actual number of items backed up may be more or less depending on velero.io/exclude-from-backup annotation, plugins returning additional related items to back up, etc.)", len(items))

	updated := backupRequest.DeepCopy()
	if updated.Status.Progress == nil {
		updated.Status.Progress = &velerov1api.BackupProgress{}
	}

	updated.Status.Progress.TotalItems = len(items)
	if err := kube.PatchResource(backupRequest.Backup, updated, kb.kbClient); err != nil {
		log.WithError(errors.WithStack((err))).Warn("Got error trying to update backup's status.progress.totalItems")
	}
	backupRequest.Status.Progress = &velerov1api.BackupProgress{TotalItems: len(items)}

	itemBackupper := &itemBackupper{
		backupRequest:            backupRequest,
		tarWriter:                tw,
		dynamicFactory:           kb.dynamicFactory,
		kbClient:                 kb.kbClient,
		discoveryHelper:          kb.discoveryHelper,
		podVolumeBackupper:       podVolumeBackupper,
		podVolumeSnapshotTracker: newPVCSnapshotTracker(),
		volumeSnapshotterGetter:  volumeSnapshotterGetter,
		itemHookHandler: &hook.DefaultItemHookHandler{
			PodCommandExecutor: kb.podCommandExecutor,
		},
	}

	// helper struct to send current progress between the main
	// backup loop and the gouroutine that periodically patches
	// the backup CR with progress updates
	type progressUpdate struct {
		totalItems, itemsBackedUp int
	}

	// the main backup process will send on this channel once
	// for every item it processes.
	update := make(chan progressUpdate)

	// the main backup process will send on this channel when
	// it's done sending progress updates
	quit := make(chan struct{})

	// This is the progress updater goroutine that receives
	// progress updates on the 'update' channel. It patches
	// the backup CR with progress updates at most every second,
	// but it will not issue a patch if it hasn't received a new
	// update since the previous patch. This goroutine exits
	// when it receives on the 'quit' channel.
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		var lastUpdate *progressUpdate
		for {
			select {
			case <-quit:
				ticker.Stop()
				return
			case val := <-update:
				lastUpdate = &val
			case <-ticker.C:
				if lastUpdate != nil {
					updated := backupRequest.DeepCopy()
					if updated.Status.Progress == nil {
						updated.Status.Progress = &velerov1api.BackupProgress{}
					}
					updated.Status.Progress.TotalItems = lastUpdate.totalItems
					updated.Status.Progress.ItemsBackedUp = lastUpdate.itemsBackedUp
					if err := kube.PatchResource(backupRequest.Backup, updated, kb.kbClient); err != nil {
						log.WithError(errors.WithStack((err))).Warn("Got error trying to update backup's status.progress")
					}
					backupRequest.Status.Progress = &velerov1api.BackupProgress{TotalItems: lastUpdate.totalItems, ItemsBackedUp: lastUpdate.itemsBackedUp}
					lastUpdate = nil
				}
			}
		}
	}()

	backedUpGroupResources := map[schema.GroupResource]bool{}

	for i, item := range items {
		log.WithFields(map[string]interface{}{
			"progress":  "",
			"resource":  item.groupResource.String(),
			"namespace": item.namespace,
			"name":      item.name,
		}).Infof("Processing item")

		// use an anonymous func so we can defer-close/remove the file
		// as soon as we're done with it
		func() {
			var unstructured unstructured.Unstructured

			f, err := os.Open(item.path)
			if err != nil {
				log.WithError(errors.WithStack(err)).Error("Error opening file containing item")
				return
			}
			defer f.Close()
			defer os.Remove(f.Name())

			if err := json.NewDecoder(f).Decode(&unstructured); err != nil {
				log.WithError(errors.WithStack(err)).Error("Error decoding JSON from file")
				return
			}

			if backedUp := kb.backupItem(log, item.groupResource, itemBackupper, &unstructured, item.preferredGVR); backedUp {
				backedUpGroupResources[item.groupResource] = true
			}
		}()

		// updated total is computed as "how many items we've backed up so far, plus
		// how many items we know of that are remaining"
		totalItems := len(backupRequest.BackedUpItems) + (len(items) - (i + 1))

		// send a progress update
		update <- progressUpdate{
			totalItems:    totalItems,
			itemsBackedUp: len(backupRequest.BackedUpItems),
		}

		log.WithFields(map[string]interface{}{
			"progress":  "",
			"resource":  item.groupResource.String(),
			"namespace": item.namespace,
			"name":      item.name,
		}).Infof("Backed up %d items out of an estimated total of %d (estimate will change throughout the backup)", len(backupRequest.BackedUpItems), totalItems)
	}

	// no more progress updates will be sent on the 'update' channel
	quit <- struct{}{}

	// back up CRD(this is a CRD definition of the resource, it's a CRD instance) for resource if found.
	// We should only need to do this if we've backed up at least one item for the resource
	// and the CRD type(this is the CRD type itself) is neither included or excluded.
	// When it's included, the resource's CRD is already handled. When it's excluded, no need to check.
	if !backupRequest.ResourceIncludesExcludes.ShouldExclude(kuberesource.CustomResourceDefinitions.String()) &&
		!backupRequest.ResourceIncludesExcludes.ShouldInclude(kuberesource.CustomResourceDefinitions.String()) {
		for gr := range backedUpGroupResources {
			kb.backupCRD(log, gr, itemBackupper)
		}
	}

	// do a final update on progress since we may have just added some CRDs and may not have updated
	// for the last few processed items.
	updated = backupRequest.DeepCopy()
	if updated.Status.Progress == nil {
		updated.Status.Progress = &velerov1api.BackupProgress{}
	}
	updated.Status.Progress.TotalItems = len(backupRequest.BackedUpItems)
	updated.Status.Progress.ItemsBackedUp = len(backupRequest.BackedUpItems)

	if err := kube.PatchResource(backupRequest.Backup, updated, kb.kbClient); err != nil {
		log.WithError(errors.WithStack((err))).Warn("Got error trying to update backup's status.progress")
	}
	skippedPVSummary, _ := json.Marshal(backupRequest.SkippedPVTracker.Summary())
	log.Infof("Summary for skipped PVs: %s", skippedPVSummary)
	backupRequest.Status.Progress = &velerov1api.BackupProgress{TotalItems: len(backupRequest.BackedUpItems), ItemsBackedUp: len(backupRequest.BackedUpItems)}
	log.WithField("progress", "").Infof("Backed up a total of %d items", len(backupRequest.BackedUpItems))

	return nil
}

func (kb *kubernetesBackupper) backupItem(log logrus.FieldLogger, gr schema.GroupResource, itemBackupper *itemBackupper, unstructured *unstructured.Unstructured, preferredGVR schema.GroupVersionResource) bool {
	backedUpItem, _, err := itemBackupper.backupItem(log, unstructured, gr, preferredGVR, false, false)
	if aggregate, ok := err.(kubeerrs.Aggregate); ok {
		log.WithField("name", unstructured.GetName()).Infof("%d errors encountered backup up item", len(aggregate.Errors()))
		// log each error separately so we get error location info in the log, and an
		// accurate count of errors
		for _, err = range aggregate.Errors() {
			log.WithError(err).WithField("name", unstructured.GetName()).Error("Error backing up item")
		}

		return false
	}
	if err != nil {
		log.WithError(err).WithField("name", unstructured.GetName()).Error("Error backing up item")
		return false
	}
	return backedUpItem
}

func (kb *kubernetesBackupper) finalizeItem(log logrus.FieldLogger, gr schema.GroupResource, itemBackupper *itemBackupper, unstructured *unstructured.Unstructured, preferredGVR schema.GroupVersionResource) (bool, []FileForArchive) {
	backedUpItem, updateFiles, err := itemBackupper.backupItem(log, unstructured, gr, preferredGVR, true, true)
	if aggregate, ok := err.(kubeerrs.Aggregate); ok {
		log.WithField("name", unstructured.GetName()).Infof("%d errors encountered backup up item", len(aggregate.Errors()))
		// log each error separately so we get error location info in the log, and an
		// accurate count of errors
		for _, err = range aggregate.Errors() {
			log.WithError(err).WithField("name", unstructured.GetName()).Error("Error backing up item")
		}

		return false, updateFiles
	}
	if err != nil {
		log.WithError(err).WithField("name", unstructured.GetName()).Error("Error backing up item")
		return false, updateFiles
	}
	return backedUpItem, updateFiles
}

// backupCRD checks if the resource is a custom resource, and if so, backs up the custom resource definition
// associated with it.
func (kb *kubernetesBackupper) backupCRD(log logrus.FieldLogger, gr schema.GroupResource, itemBackupper *itemBackupper) {
	crdGroupResource := kuberesource.CustomResourceDefinitions

	log.Debugf("Getting server preferred API version for %s", crdGroupResource)
	gvr, apiResource, err := kb.discoveryHelper.ResourceFor(crdGroupResource.WithVersion(""))
	if err != nil {
		log.WithError(errors.WithStack(err)).Errorf("Error getting resolved resource for %s", crdGroupResource)
		return
	}
	log.Debugf("Got server preferred API version %s for %s", gvr.Version, crdGroupResource)

	log.Debugf("Getting dynamic client for %s", gvr.String())
	crdClient, err := kb.dynamicFactory.ClientForGroupVersionResource(gvr.GroupVersion(), apiResource, "")
	if err != nil {
		log.WithError(errors.WithStack(err)).Errorf("Error getting dynamic client for %s", crdGroupResource)
		return
	}
	log.Debugf("Got dynamic client for %s", gvr.String())

	// try to get a CRD whose name matches the provided GroupResource
	unstructured, err := crdClient.Get(gr.String(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// not found: this means the GroupResource provided was not a
		// custom resource, so there's no CRD to back up.
		log.Debugf("No CRD found for GroupResource %s", gr.String())
		return
	}
	if err != nil {
		log.WithError(errors.WithStack(err)).Errorf("Error getting CRD %s", gr.String())
		return
	}

	log.Infof("Found associated CRD %s to add to backup", gr.String())

	kb.backupItem(log, gvr.GroupResource(), itemBackupper, unstructured, gvr)
}

func (kb *kubernetesBackupper) writeBackupVersion(tw *tar.Writer) error {
	versionFile := filepath.Join(velerov1api.MetadataDir, "version")
	versionString := fmt.Sprintf("%s\n", BackupFormatVersion)

	hdr := &tar.Header{
		Name:     versionFile,
		Size:     int64(len(versionString)),
		Typeflag: tar.TypeReg,
		Mode:     0755,
		ModTime:  time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.WithStack(err)
	}
	if _, err := tw.Write([]byte(versionString)); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (kb *kubernetesBackupper) FinalizeBackup(log logrus.FieldLogger,
	backupRequest *Request,
	inBackupFile io.Reader,
	outBackupFile io.Writer,
	backupItemActionResolver framework.BackupItemActionResolverV2,
	asyncBIAOperations []*itemoperation.BackupOperation) error {
	gzw := gzip.NewWriter(outBackupFile)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	gzr, err := gzip.NewReader(inBackupFile)
	if err != nil {
		log.Infof("error creating gzip reader: %v", err)
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	backupRequest.ResolvedActions, err = backupItemActionResolver.ResolveActions(kb.discoveryHelper, log)
	if err != nil {
		log.WithError(errors.WithStack(err)).Debugf("Error from backupItemActionResolver.ResolveActions")
		return err
	}

	backupRequest.BackedUpItems = map[itemKey]struct{}{}

	// set up a temp dir for the itemCollector to use to temporarily
	// store items as they're scraped from the API.
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		return errors.Wrap(err, "error creating temp dir for backup")
	}
	defer os.RemoveAll(tempDir)

	collector := &itemCollector{
		log:                   log,
		backupRequest:         backupRequest,
		discoveryHelper:       kb.discoveryHelper,
		dynamicFactory:        kb.dynamicFactory,
		cohabitatingResources: cohabitatingResources(),
		dir:                   tempDir,
		pageSize:              kb.clientPageSize,
	}

	// Get item list from itemoperation.BackupOperation.Spec.PostOperationItems
	var resourceIDs []velero.ResourceIdentifier
	for _, operation := range asyncBIAOperations {
		if len(operation.Spec.PostOperationItems) != 0 {
			resourceIDs = append(resourceIDs, operation.Spec.PostOperationItems...)
		}
	}
	items := collector.getItemsFromResourceIdentifiers(resourceIDs)
	log.WithField("progress", "").Infof("Collected %d items from the async BIA operations PostOperationItems list", len(items))

	itemBackupper := &itemBackupper{
		backupRequest:            backupRequest,
		tarWriter:                tw,
		dynamicFactory:           kb.dynamicFactory,
		kbClient:                 kb.kbClient,
		discoveryHelper:          kb.discoveryHelper,
		itemHookHandler:          &hook.NoOpItemHookHandler{},
		podVolumeSnapshotTracker: newPVCSnapshotTracker(),
	}
	updateFiles := make(map[string]FileForArchive)
	backedUpGroupResources := map[schema.GroupResource]bool{}

	for i, item := range items {
		log.WithFields(map[string]interface{}{
			"progress":  "",
			"resource":  item.groupResource.String(),
			"namespace": item.namespace,
			"name":      item.name,
		}).Infof("Processing item")

		// use an anonymous func so we can defer-close/remove the file
		// as soon as we're done with it
		func() {
			var unstructured unstructured.Unstructured

			f, err := os.Open(item.path)
			if err != nil {
				log.WithError(errors.WithStack(err)).Error("Error opening file containing item")
				return
			}
			defer f.Close()
			defer os.Remove(f.Name())

			if err := json.NewDecoder(f).Decode(&unstructured); err != nil {
				log.WithError(errors.WithStack(err)).Error("Error decoding JSON from file")
				return
			}

			backedUp, itemFiles := kb.finalizeItem(log, item.groupResource, itemBackupper, &unstructured, item.preferredGVR)
			if backedUp {
				backedUpGroupResources[item.groupResource] = true
				for _, itemFile := range itemFiles {
					updateFiles[itemFile.FilePath] = itemFile
				}
			}
		}()

		// updated total is computed as "how many items we've backed up so far, plus
		// how many items we know of that are remaining"
		totalItems := len(backupRequest.BackedUpItems) + (len(items) - (i + 1))

		log.WithFields(map[string]interface{}{
			"progress":  "",
			"resource":  item.groupResource.String(),
			"namespace": item.namespace,
			"name":      item.name,
		}).Infof("Updated %d items out of an estimated total of %d (estimate will change throughout the backup finalizer)", len(backupRequest.BackedUpItems), totalItems)
	}

	// write new tar archive replacing files in original with content updateFiles for matches
	if err := buildFinalTarball(tr, tw, updateFiles); err != nil {
		log.Errorf("Error building final tarball: %s", err.Error())
		return err
	}

	log.WithField("progress", "").Infof("Updated a total of %d items", len(backupRequest.BackedUpItems))

	return nil
}

func buildFinalTarball(tr *tar.Reader, tw *tar.Writer, updateFiles map[string]FileForArchive) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.WithStack(err)
		}
		newFile, ok := updateFiles[header.Name]
		if ok {
			// add updated file to archive, skip over tr file content
			if err := tw.WriteHeader(newFile.Header); err != nil {
				return errors.WithStack(err)
			}
			if _, err := tw.Write(newFile.FileBytes); err != nil {
				return errors.WithStack(err)
			}
			delete(updateFiles, header.Name)
			// skip over file contents from old tarball
			_, err := io.ReadAll(tr)
			if err != nil {
				return errors.WithStack(err)
			}
		} else {
			// Add original content to new tarball, as item wasn't updated
			oldContents, err := io.ReadAll(tr)
			if err != nil {
				return errors.WithStack(err)
			}
			if err := tw.WriteHeader(header); err != nil {
				return errors.WithStack(err)
			}
			if _, err := tw.Write(oldContents); err != nil {
				return errors.WithStack(err)
			}
		}
	}
	// iterate over any remaining map entries, which represent updated items that
	// were not in the original backup tarball
	for _, newFile := range updateFiles {
		if err := tw.WriteHeader(newFile.Header); err != nil {
			return errors.WithStack(err)
		}
		if _, err := tw.Write(newFile.FileBytes); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

type tarWriter interface {
	io.Closer
	Write([]byte) (int, error)
	WriteHeader(*tar.Header) error
}

func getNamespacesManagedByArgoCD(kbClient kbclient.Client, includedNamespaces []string, log logrus.FieldLogger) []string {
	var nsManagedByArgoCD []string

	for _, nsName := range includedNamespaces {
		ns := corev1api.Namespace{}
		if err := kbClient.Get(context.Background(), kbclient.ObjectKey{Name: nsName}, &ns); err != nil {
			// check for only those ns that exist and are included in backup
			// here we ignore cases like "" or "*" specified under includedNamespaces
			if apierrors.IsNotFound(err) {
				continue
			}
			log.WithError(err).Errorf("error getting namespace %s", nsName)
			continue
		}

		nsLabels := ns.GetLabels()
		if len(nsLabels[ArgoCDManagedByNamespaceLabel]) > 0 {
			nsManagedByArgoCD = append(nsManagedByArgoCD, nsName)
		}
	}
	return nsManagedByArgoCD
}
