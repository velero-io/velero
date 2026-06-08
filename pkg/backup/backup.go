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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/internal/volume"
	"github.com/vmware-tanzu/velero/internal/volumehelper"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/itemblock"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
	ibav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/itemblockaction/v1"
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
	Backup(
		logger logrus.FieldLogger,
		backup *Request,
		backupFile io.Writer,
		actions []biav2.BackupItemAction,
		itemBlockActions []ibav1.ItemBlockAction,
		volumeSnapshotterGetter VolumeSnapshotterGetter,
	) error

	BackupWithResolvers(
		log logrus.FieldLogger,
		backupRequest *Request,
		backupFile io.Writer,
		backupItemActionResolver framework.BackupItemActionResolverV2,
		itemBlockActionResolver framework.ItemBlockActionResolver,
		volumeSnapshotterGetter VolumeSnapshotterGetter,
	) error

	FinalizeBackup(
		log logrus.FieldLogger,
		backupRequest *Request,
		inBackupFile io.Reader,
		outBackupFile io.Writer,
		backupItemActionResolver framework.BackupItemActionResolverV2,
		asyncBIAOperations []*itemoperation.BackupOperation,
		backupStore persistence.BackupStore,
	) error
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
	pluginManager             func(logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter         persistence.ObjectBackupStoreGetter
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
	pluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
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
		pluginManager:             pluginManager,
		backupStoreGetter:         backupStoreGetter,
	}, nil
}

// getNamespaceIncludesExcludes returns an IncludesExcludes list containing which namespaces to
// include and exclude from the backup.
func getNamespaceIncludesExcludes(backup *velerov1api.Backup, kbClient kbclient.Client) (*collections.NamespaceIncludesExcludes, error) {
	nsList := corev1api.NamespaceList{}
	if err := kbClient.List(context.Background(), &nsList); err != nil {
		return nil, err
	}

	activeNamespaces := []string{}
	for _, ns := range nsList.Items {
		activeNamespaces = append(activeNamespaces, ns.Name)
	}

	// Set ActiveNamespaces first, then set includes/excludes
	includesExcludes := collections.NewNamespaceIncludesExcludes().
		ActiveNamespaces(activeNamespaces).
		Includes(backup.Spec.IncludedNamespaces...).
		Excludes(backup.Spec.ExcludedNamespaces...)

	// Expand wildcards if needed
	if err := includesExcludes.ExpandIncludesExcludes(); err != nil {
		return nil, err
	}

	return includesExcludes, nil
}

// getArgoCDManagedNamespaces returns a list of namespaces managed by ArgoCD that should be included in the backup.
func getArgoCDManagedNamespaces(kbClient kbclient.Client, includesExcludes *collections.NamespaceIncludesExcludes) ([]string, error) {
	nsList := corev1api.NamespaceList{}
	if err := kbClient.List(context.Background(), &nsList); err != nil {
		return nil, err
	}

	nsManagedByArgoCD := []string{}
	for _, ns := range nsList.Items {
		nsLabels := ns.GetLabels()
		if len(nsLabels[ArgoCDManagedByNamespaceLabel]) > 0 && includesExcludes.ShouldInclude(ns.Name) {
			nsManagedByArgoCD = append(nsManagedByArgoCD, ns.Name)
		}
	}

	return nsManagedByArgoCD, nil
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
	actions []biav2.BackupItemAction, itemBlockActions []ibav1.ItemBlockAction, volumeSnapshotterGetter VolumeSnapshotterGetter) error {
	backupItemActions := framework.NewBackupItemActionResolverV2(actions)
	itemBlockActionResolver := framework.NewItemBlockActionResolver(itemBlockActions)
	return kb.BackupWithResolvers(log, backupRequest, backupFile, backupItemActions, itemBlockActionResolver, volumeSnapshotterGetter)
}

func (kb *kubernetesBackupper) BackupWithResolvers(
	log logrus.FieldLogger,
	backupRequest *Request,
	backupFile io.Writer,
	backupItemActionResolver framework.BackupItemActionResolverV2,
	itemBlockActionResolver framework.ItemBlockActionResolver,
	volumeSnapshotterGetter VolumeSnapshotterGetter,
) error {
	gzippedData := gzip.NewWriter(backupFile)
	defer gzippedData.Close()

	tw := NewTarWriter(tar.NewWriter(gzippedData))
	defer tw.Close()

	log.Info("Writing backup version file")
	if err := kb.writeBackupVersion(tw); err != nil {
		return errors.WithStack(err)
	}
	var err error
	backupRequest.NamespaceIncludesExcludes, err = getNamespaceIncludesExcludes(backupRequest.Backup, kb.kbClient)
	if err != nil {
		log.WithError(err).Errorf("error getting namespace includes/excludes")
		return err
	}

	nsManagedByArgoCD, err := getArgoCDManagedNamespaces(kb.kbClient, backupRequest.NamespaceIncludesExcludes)
	if err != nil {
		log.WithError(err).Errorf("error getting ArgoCD managed namespaces")
		return err
	}

	if backupRequest.NamespaceIncludesExcludes.IsWildcardExpanded() {
		expandedIncludes := backupRequest.NamespaceIncludesExcludes.GetIncludes()
		expandedExcludes := backupRequest.NamespaceIncludesExcludes.GetExcludes()

		// Get the final namespace list after wildcard expansion
		wildcardResult, err := backupRequest.NamespaceIncludesExcludes.ResolveNamespaceList()
		if err != nil {
			log.WithError(err).Errorf("error resolving namespace list")
			return err
		}

		if len(wildcardResult) == 0 {
			log.Warnf("no namespaces matched the resolution of wildcard patterns ")
		}

		log.WithFields(logrus.Fields{
			"expandedIncludes": expandedIncludes,
			"expandedExcludes": expandedExcludes,
			"wildcardResult":   wildcardResult,
			"includedCount":    len(expandedIncludes),
			"excludedCount":    len(expandedExcludes),
			"resultCount":      len(wildcardResult),
		}).Info("Successfully expanded wildcard patterns")
	}

	log.Infof("Including namespaces: %s", backupRequest.NamespaceIncludesExcludes.IncludesString())
	log.Infof("Excluding namespaces: %s", backupRequest.NamespaceIncludesExcludes.ExcludesString())

	// check if there are any namespaces included in the backup which are managed by argoCD
	// We will check for the existence of a ArgoCD label in the includedNamespaces and add a warning
	// so that users are at least aware about the existence of argoCD managed ns in their backup
	// Related Issue: https://github.com/vmware-tanzu/velero/issues/7905
	if len(nsManagedByArgoCD) > 0 {
		log.Warnf("backup operation may encounter complications and potentially produce undesirable results due to the inclusion of namespaces %v managed by ArgoCD in the backup.", nsManagedByArgoCD)
	}

	if collections.UseOldResourceFilters(backupRequest.Spec) {
		backupRequest.ResourceIncludesExcludes = collections.GetGlobalResourceIncludesExcludes(kb.discoveryHelper, log,
			backupRequest.Spec.IncludedResources,
			backupRequest.Spec.ExcludedResources,
			backupRequest.Spec.IncludeClusterResources,
			*backupRequest.NamespaceIncludesExcludes)
	} else {
		srie := collections.GetScopeResourceIncludesExcludes(kb.discoveryHelper, log,
			backupRequest.Spec.IncludedNamespaceScopedResources,
			backupRequest.Spec.ExcludedNamespaceScopedResources,
			backupRequest.Spec.IncludedClusterScopedResources,
			backupRequest.Spec.ExcludedClusterScopedResources,
			*backupRequest.NamespaceIncludesExcludes,
		)
		if backupRequest.ResPolicies != nil {
			srie.CombineWithPolicy(backupRequest.ResPolicies.GetIncludeExcludePolicy())
		}
		backupRequest.ResourceIncludesExcludes = srie
	}

	log.Infof("Backing up all volumes using pod volume backup: %t", boolptr.IsSetToTrue(backupRequest.Backup.Spec.DefaultVolumesToFsBackup))

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

	backupRequest.ResolvedItemBlockActions, err = itemBlockActionResolver.ResolveActions(kb.discoveryHelper, log)
	if err != nil {
		log.WithError(errors.WithStack(err)).Errorf("Error from itemBlockActionResolver.ResolveActions")
		return err
	}

	podVolumeTimeout := kb.podVolumeTimeout
	if val := backupRequest.Annotations[velerov1api.PodVolumeOperationTimeoutAnnotation]; val != "" {
		parsed, err := time.ParseDuration(val)
		if err != nil {
			log.WithError(errors.WithStack(err)).Errorf("Unable to parse pod volume timeout annotation %s, using server value.", val)
		} else {
			podVolumeTimeout = parsed
		}
	}

	var podVolumeCancelFunc context.CancelFunc
	podVolumeContext, podVolumeCancelFunc := context.WithTimeout(context.Background(), podVolumeTimeout)
	defer podVolumeCancelFunc()

	var podVolumeBackupper podvolume.Backupper
	if kb.podVolumeBackupperFactory != nil {
		podVolumeBackupper, err = kb.podVolumeBackupperFactory.NewBackupper(podVolumeContext, log, backupRequest.Backup, kb.uploaderType)
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

	updated := backupRequest.Backup.DeepCopy()
	if updated.Status.Progress == nil {
		updated.Status.Progress = &velerov1api.BackupProgress{}
	}

	updated.Status.Progress.TotalItems = len(items)
	if err := kube.PatchResource(backupRequest.Backup, updated, kb.kbClient); err != nil {
		log.WithError(errors.WithStack((err))).Warn("Got error trying to update backup's status.progress.totalItems")
	}
	backupRequest.Status.Progress = &velerov1api.BackupProgress{TotalItems: len(items)}

	// Resolve namespaces for PVC-to-Pod cache building in volumehelper.
	// See issue #9179 for details.
	namespaces, err := backupRequest.NamespaceIncludesExcludes.ResolveNamespaceList()
	if err != nil {
		log.WithError(err).Error("Failed to resolve namespace list for PVC-to-Pod cache")
		return err
	}

	volumeHelperImpl, err := volumehelper.NewVolumeHelperImplWithNamespaces(
		backupRequest.ResPolicies,
		backupRequest.Spec.SnapshotVolumes,
		log,
		kb.kbClient,
		boolptr.IsSetToTrue(backupRequest.Spec.DefaultVolumesToFsBackup),
		!backupRequest.ResourceIncludesExcludes.ShouldInclude(kuberesource.PersistentVolumeClaims.String()),
		namespaces,
	)
	if err != nil {
		log.WithError(err).Error("Failed to build PVC-to-Pod cache for volume policy lookups")
		return err
	}

	itemBackupper := &itemBackupper{
		backupRequest:            backupRequest,
		tarWriter:                tw,
		dynamicFactory:           kb.dynamicFactory,
		kbClient:                 kb.kbClient,
		discoveryHelper:          kb.discoveryHelper,
		podVolumeBackupper:       podVolumeBackupper,
		podVolumeContext:         podVolumeContext,
		podVolumeSnapshotTracker: podvolume.NewTracker(),
		volumeSnapshotterCache:   NewVolumeSnapshotterCache(volumeSnapshotterGetter),
		itemHookHandler: &hook.DefaultItemHookHandler{
			PodCommandExecutor: kb.podCommandExecutor,
		},
		hookTracker:         hook.NewHookTracker(),
		volumeHelperImpl:    volumeHelperImpl,
		kubernetesBackupper: kb,
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
					updated := backupRequest.Backup.DeepCopy()
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

	responseCtx, responseCancel := context.WithCancel(context.Background())

	backedUpGroupResources := map[schema.GroupResource]bool{}
	// Maps items in the item list from GR+NamespacedName to a slice of pointers to kubernetesResources
	// We need the slice value since if the EnableAPIGroupVersions feature flag is set, there may
	// be more than one resource to back up for the given item.
	itemsMap := make(map[velero.ResourceIdentifier][]*kubernetesResource)
	for i := range items {
		key := velero.ResourceIdentifier{
			GroupResource: items[i].groupResource,
			Namespace:     items[i].namespace,
			Name:          items[i].name,
		}
		itemsMap[key] = append(itemsMap[key], items[i])
		// add to total items for progress reporting
		if items[i].kind != "" {
			backupRequest.BackedUpItems.AddItemToTotal(itemKey{
				resource:  fmt.Sprintf("%s/%s", items[i].preferredGVR.GroupVersion().String(), items[i].kind),
				namespace: items[i].namespace,
				name:      items[i].name,
			})
		}
	}

	var itemBlock *BackupItemBlock
	itemBlockReturn := make(chan ItemBlockReturn, 100)
	wg := &sync.WaitGroup{}
	// Handle returns from worker pool processing ItemBlocks
	go func() {
		for {
			select {
			case response := <-itemBlockReturn: // process each BackupItemBlock response
				func() {
					defer wg.Done()
					if response.err != nil {
						log.WithError(errors.WithStack((response.err))).Error("Got error in BackupItemBlock.")
					}
					for _, backedUpGR := range response.resources {
						backedUpGroupResources[backedUpGR] = true
					}
					// We could eventually track which itemBlocks have finished
					// using response.itemBlock

					// updated total is computed as "how many items we've backed up so far,
					// plus how many items are processed but not yet backed up plus how many
					// we know of that are remaining to be processed"
					backedUpItems, totalItems := backupRequest.BackedUpItems.BackedUpAndTotalLen()

					// send a progress update
					update <- progressUpdate{
						totalItems:    totalItems,
						itemsBackedUp: backedUpItems,
					}

					if len(response.itemBlock.Items) > 0 {
						log.WithFields(map[string]any{
							"progress":  "",
							"kind":      response.itemBlock.Items[0].Item.GroupVersionKind().GroupKind().String(),
							"namespace": response.itemBlock.Items[0].Item.GetNamespace(),
							"name":      response.itemBlock.Items[0].Item.GetName(),
						}).Infof("Backed up %d items out of an estimated total of %d (estimate will change throughout the backup)", backedUpItems, totalItems)
					}
				}()
			case <-responseCtx.Done():
				return
			}
		}
	}()

	for i := range items {
		log.WithFields(map[string]any{
			"progress":  "",
			"resource":  items[i].groupResource.String(),
			"namespace": items[i].namespace,
			"name":      items[i].name,
		}).Infof("Processing item")

		// Skip if this item has already been processed (in a block or previously excluded)
		if items[i].inItemBlockOrExcluded {
			log.Debugf("Not creating new ItemBlock for %s %s/%s because it's already in an ItemBlock", items[i].groupResource.String(), items[i].namespace, items[i].name)
		} else {
			if itemBlock == nil {
				itemBlock = NewBackupItemBlock(log, itemBackupper)
			}
			var newBlockItem *unstructured.Unstructured

			// If the EnableAPIGroupVersions feature flag is set, there could be multiple versions
			// of this item to be backed up. Include all of them in the same ItemBlock
			key := velero.ResourceIdentifier{
				GroupResource: items[i].groupResource,
				Namespace:     items[i].namespace,
				Name:          items[i].name,
			}
			allVersionsOfItem := itemsMap[key]
			for _, itemVersion := range allVersionsOfItem {
				unstructured := itemBlock.addKubernetesResource(itemVersion, log)
				if newBlockItem == nil {
					newBlockItem = unstructured
				}
			}
			// call GetRelatedItems, add found items to block if not in block, recursively until no more items
			if newBlockItem != nil {
				kb.executeItemBlockActions(log, newBlockItem, items[i].groupResource, items[i].name, items[i].namespace, itemsMap, itemBlock)
			}
		}

		// We skip calling backupItemBlock here so that we will add the next item to the current ItemBlock if:
		// 1) This is not the last item to be processed
		// 2) Both current and next item are ordered resources
		// 3) Both current and next item are for the same GroupResource
		addNextToBlock := i < len(items)-1 && items[i].orderedResource && items[i+1].orderedResource && items[i].groupResource == items[i+1].groupResource
		if itemBlock != nil && len(itemBlock.Items) > 0 && !addNextToBlock {
			log.Infof("Backing Up Item Block including %s %s/%s (%v items in block)", items[i].groupResource.String(), items[i].namespace, items[i].name, len(itemBlock.Items))

			wg.Add(1)
			backupRequest.WorkerPool.GetInputChannel() <- ItemBlockInput{
				itemBlock:  itemBlock,
				returnChan: itemBlockReturn,
			}
			itemBlock = nil
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	// Wait for all the ItemBlocks to be processed
	select {
	case <-done:
		log.Info("done processing ItemBlocks")
	case <-responseCtx.Done():
		log.Info("ItemBlock processing canceled")
	}
	// cancel response-processing goroutine
	responseCancel()

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

	processedPVBs := itemBackupper.podVolumeBackupper.WaitAllPodVolumesProcessed(log)
	backupRequest.PodVolumeBackups = append(backupRequest.PodVolumeBackups, processedPVBs...)

	// do a final update on progress since we may have just added some CRDs and may not have updated
	// for the last few processed items.
	updated = backupRequest.Backup.DeepCopy()
	if updated.Status.Progress == nil {
		updated.Status.Progress = &velerov1api.BackupProgress{}
	}
	backedUpItems := backupRequest.BackedUpItems.Len()
	updated.Status.Progress.TotalItems = backedUpItems
	updated.Status.Progress.ItemsBackedUp = backedUpItems

	// update the hooks execution status
	if updated.Status.HookStatus == nil {
		updated.Status.HookStatus = &velerov1api.HookStatus{}
	}
	updated.Status.HookStatus.HooksAttempted, updated.Status.HookStatus.HooksFailed = itemBackupper.hookTracker.Stat()
	log.Debugf("hookAttempted: %d, hookFailed: %d", updated.Status.HookStatus.HooksAttempted, updated.Status.HookStatus.HooksFailed)

	if err := kube.PatchResource(backupRequest.Backup, updated, kb.kbClient); err != nil {
		log.WithError(errors.WithStack((err))).Warn("Got error trying to update backup's status.progress and hook status")
	}

	if skippedPVSummary, err := json.Marshal(backupRequest.SkippedPVTracker.Summary()); err != nil {
		log.WithError(errors.WithStack(err)).Warn("Fail to generate skipped PV summary.")
	} else {
		log.Infof("Summary for skipped PVs: %s", skippedPVSummary)
	}

	backupRequest.Status.Progress = &velerov1api.BackupProgress{TotalItems: backedUpItems, ItemsBackedUp: backedUpItems}
	log.WithField("progress", "").Infof("Backed up a total of %d items", backedUpItems)

	return nil
}

func (kb *kubernetesBackupper) executeItemBlockActions(
	log logrus.FieldLogger,
	obj runtime.Unstructured,
	groupResource schema.GroupResource,
	name, namespace string,
	itemsMap map[velero.ResourceIdentifier][]*kubernetesResource,
	itemBlock *BackupItemBlock,
) {
	metadata, err := meta.Accessor(obj)
	if err != nil {
		log.WithError(errors.WithStack(err)).Warn("Failed to get object metadata.")
		return
	}
	for _, action := range itemBlock.itemBackupper.backupRequest.ResolvedItemBlockActions {
		if !action.ShouldUse(groupResource, namespace, metadata, log) {
			continue
		}
		log.Info("Executing ItemBlock action")

		relatedItems, err := action.GetRelatedItems(obj, itemBlock.itemBackupper.backupRequest.Backup)
		if err != nil {
			log.Error(errors.Wrapf(err, "error executing ItemBlock action (groupResource=%s, namespace=%s, name=%s)", groupResource.String(), namespace, name))
			continue
		}

		for _, relatedItem := range relatedItems {
			var newBlockItem *unstructured.Unstructured
			// Look for item in itemsMap
			itemsToAdd := itemsMap[relatedItem]
			// if item is in the item collector list, we'll have at least one element.
			// If EnableAPIGroupVersions is set, we may have more than one.
			// If we get an unstructured obj back from addKubernetesResource, then it wasn't
			// already in a block and we recursively look for related items in the returned item.
			if len(itemsToAdd) > 0 {
				for _, itemToAdd := range itemsToAdd {
					unstructured := itemBlock.addKubernetesResource(itemToAdd, log)
					if newBlockItem == nil {
						newBlockItem = unstructured
					}
				}
				if newBlockItem != nil {
					kb.executeItemBlockActions(log, newBlockItem, relatedItem.GroupResource, relatedItem.Name, relatedItem.Namespace, itemsMap, itemBlock)
				}
				continue
			}
			// Item wasn't found in item collector list, get from cluster
			gvr, resource, err := itemBlock.itemBackupper.discoveryHelper.ResourceFor(relatedItem.GroupResource.WithVersion(""))
			if err != nil {
				log.Error(errors.Wrapf(err, "Unable to obtain gvr and resource for related item %s %s/%s", relatedItem.GroupResource.String(), relatedItem.Namespace, relatedItem.Name))
				continue
			}

			client, err := itemBlock.itemBackupper.dynamicFactory.ClientForGroupVersionResource(gvr.GroupVersion(), resource, relatedItem.Namespace)
			if err != nil {
				log.Error(errors.Wrapf(err, "Unable to obtain client for gvr %s %s (%s)", gvr.GroupVersion(), resource.Name, relatedItem.Namespace))
				continue
			}

			item, err := client.Get(relatedItem.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				log.WithFields(logrus.Fields{
					"groupResource": relatedItem.GroupResource,
					"namespace":     relatedItem.Namespace,
					"name":          relatedItem.Name,
				}).Warnf("Related item was not found in Kubernetes API, can't add to item block")
				continue
			}
			if err != nil {
				log.Error(errors.Wrapf(err, "Error while trying to get related item %s %s/%s from cluster", relatedItem.GroupResource.String(), relatedItem.Namespace, relatedItem.Name))
				continue
			}
			itemsMap[relatedItem] = append(itemsMap[relatedItem], &kubernetesResource{
				groupResource:         relatedItem.GroupResource,
				preferredGVR:          gvr,
				namespace:             relatedItem.Namespace,
				name:                  relatedItem.Name,
				inItemBlockOrExcluded: true,
			})

			relatedItemMetadata, err := meta.Accessor(item)
			if err != nil {
				log.WithError(errors.WithStack(err)).Warn("Failed to get object metadata.")
				continue
			}
			// Don't add to ItemBlock if item is excluded
			// itemInclusionChecks logs the reason
			if !itemBlock.itemBackupper.itemInclusionChecks(log, false, relatedItemMetadata, item, relatedItem.GroupResource) {
				continue
			}
			log.Infof("adding %s %s/%s to ItemBlock", relatedItem.GroupResource, relatedItem.Namespace, relatedItem.Name)
			itemBlock.AddUnstructured(relatedItem.GroupResource, item, gvr)
			kb.executeItemBlockActions(log, item, relatedItem.GroupResource, relatedItem.Name, relatedItem.Namespace, itemsMap, itemBlock)
		}
	}
}

func (kb *kubernetesBackupper) backupItemBlock(itemBlock *BackupItemBlock) []schema.GroupResource {
	// find pods in ItemBlock
	// filter pods based on whether they still need to be backed up
	// this list will be used to run pre/post hooks
	var preHookPods []itemblock.ItemBlockItem
	itemBlock.Log.Debug("Executing pre hooks")
	for _, item := range itemBlock.Items {
		if item.Gr == kuberesource.Pods {
			key, err := kb.getItemKey(item)
			if err != nil {
				itemBlock.Log.WithError(errors.WithStack(err)).Error("Error accessing pod metadata")
				continue
			}
			// Don't run hooks if pod has already been backed up
			if !itemBlock.itemBackupper.backupRequest.BackedUpItems.Has(key) {
				preHookPods = append(preHookPods, item)
			}
		}
	}
	postHookPods, failedPods, errs := kb.handleItemBlockPreHooks(itemBlock, preHookPods)
	for i, pod := range failedPods {
		itemBlock.Log.WithError(errs[i]).WithField("name", pod.Item.GetName()).Error("Error running pre hooks for pod")
		// if pre hook fails, flag pod as backed-up and move on
		key, err := kb.getItemKey(pod)
		if err != nil {
			itemBlock.Log.WithError(errors.WithStack(err)).Error("Error accessing pod metadata")
			continue
		}
		itemBlock.itemBackupper.backupRequest.BackedUpItems.AddItem(key)
	}

	itemBlock.Log.Debug("Backing up items in BackupItemBlock")
	var grList []schema.GroupResource
	for _, item := range itemBlock.Items {
		if backedUp := kb.backupItem(itemBlock.Log, item.Gr, itemBlock.itemBackupper, item.Item, item.PreferredGVR, itemBlock); backedUp {
			grList = append(grList, item.Gr)
		}
	}

	if len(postHookPods) > 0 {
		itemBlock.Log.Debug("Executing post hooks")
		kb.handleItemBlockPostHooks(itemBlock, postHookPods)
	}

	return grList
}

func (kb *kubernetesBackupper) getItemKey(item itemblock.ItemBlockItem) (itemKey, error) {
	metadata, err := meta.Accessor(item.Item)
	if err != nil {
		return itemKey{}, err
	}
	key := itemKey{
		resource:  resourceKey(item.Item),
		namespace: metadata.GetNamespace(),
		name:      metadata.GetName(),
	}
	return key, nil
}

func (kb *kubernetesBackupper) handleItemBlockPreHooks(itemBlock *BackupItemBlock, hookPods []itemblock.ItemBlockItem) ([]itemblock.ItemBlockItem, []itemblock.ItemBlockItem, []error) {
	var successPods []itemblock.ItemBlockItem
	var failedPods []itemblock.ItemBlockItem
	var errs []error
	for _, pod := range hookPods {
		err := itemBlock.itemBackupper.itemHookHandler.HandleHooks(itemBlock.Log, pod.Gr, pod.Item, itemBlock.itemBackupper.backupRequest.ResourceHooks, hook.PhasePre, itemBlock.itemBackupper.hookTracker)
		if err == nil {
			successPods = append(successPods, pod)
		} else {
			failedPods = append(failedPods, pod)
			errs = append(errs, err)
		}
	}
	return successPods, failedPods, errs
}

// The hooks cannot execute until the PVBs to be processed
func (kb *kubernetesBackupper) handleItemBlockPostHooks(itemBlock *BackupItemBlock, hookPods []itemblock.ItemBlockItem) {
	log := itemBlock.Log

	// the post hooks will not execute until all PVBs of the item block pods are processed
	if err := kb.waitUntilPVBsProcessed(itemBlock.itemBackupper.podVolumeContext, log, itemBlock, hookPods); err != nil {
		log.WithError(err).Error("failed to wait PVBs processed for the ItemBlock")
		return
	}

	for _, pod := range hookPods {
		if err := itemBlock.itemBackupper.itemHookHandler.HandleHooks(itemBlock.Log, pod.Gr, pod.Item, itemBlock.itemBackupper.backupRequest.ResourceHooks,
			hook.PhasePost, itemBlock.itemBackupper.hookTracker); err != nil {
			log.WithError(err).WithField("name", pod.Item.GetName()).Error("Error running post hooks for pod")
		}
	}
}

// wait all PVBs of the item block pods to be processed
func (kb *kubernetesBackupper) waitUntilPVBsProcessed(ctx context.Context, log logrus.FieldLogger, itemBlock *BackupItemBlock, pods []itemblock.ItemBlockItem) error {
	pvbMap := map[*velerov1api.PodVolumeBackup]bool{}
	for _, pod := range pods {
		namespace, name := pod.Item.GetNamespace(), pod.Item.GetName()
		pvbs, err := itemBlock.itemBackupper.podVolumeBackupper.ListPodVolumeBackupsByPod(namespace, name)
		if err != nil {
			return errors.Wrapf(err, "failed to list PodVolumeBackups for pod %s/%s", namespace, name)
		}
		for _, pvb := range pvbs {
			pvbMap[pvb] = pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseCompleted ||
				pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseFailed ||
				pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseCanceled
		}
	}

	checkFunc := func(context.Context) (done bool, err error) {
		allProcessed := true
		for pvb, processed := range pvbMap {
			if processed {
				continue
			}
			updatedPVB, err := itemBlock.itemBackupper.podVolumeBackupper.GetPodVolumeBackupByPodAndVolume(pvb.Spec.Pod.Namespace, pvb.Spec.Pod.Name, pvb.Spec.Volume)
			if err != nil {
				allProcessed = false
				log.Infof("failed to get PVB: %v", err)
				continue
			}
			if updatedPVB.Status.Phase == velerov1api.PodVolumeBackupPhaseCompleted ||
				updatedPVB.Status.Phase == velerov1api.PodVolumeBackupPhaseFailed ||
				updatedPVB.Status.Phase == velerov1api.PodVolumeBackupPhaseCanceled {
				pvbMap[pvb] = true
				continue
			}
			allProcessed = false
		}

		return allProcessed, nil
	}

	return wait.PollUntilContextCancel(ctx, 5*time.Second, true, checkFunc)
}

func (kb *kubernetesBackupper) backupItem(log logrus.FieldLogger, gr schema.GroupResource, itemBackupper *itemBackupper, unstructured *unstructured.Unstructured, preferredGVR schema.GroupVersionResource, itemBlock *BackupItemBlock) bool {
	backedUpItem, _, err := itemBackupper.backupItem(log, unstructured, gr, preferredGVR, false, false, itemBlock)
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

func (kb *kubernetesBackupper) finalizeItem(
	log logrus.FieldLogger,
	gr schema.GroupResource,
	itemBackupper *itemBackupper,
	unstructured *unstructured.Unstructured,
	preferredGVR schema.GroupVersionResource,
) (bool, []FileForArchive) {
	backedUpItem, updateFiles, err := itemBackupper.backupItem(log, unstructured, gr, preferredGVR, true, true, nil)
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

	kb.backupItem(log, gvr.GroupResource(), itemBackupper, unstructured, gvr, nil)
}

func (kb *kubernetesBackupper) writeBackupVersion(tw tarWriter) error {
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

func (kb *kubernetesBackupper) FinalizeBackup(
	log logrus.FieldLogger,
	backupRequest *Request,
	inBackupFile io.Reader,
	outBackupFile io.Writer,
	backupItemActionResolver framework.BackupItemActionResolverV2,
	asyncBIAOperations []*itemoperation.BackupOperation,
	backupStore persistence.BackupStore,
) error {
	gzw := gzip.NewWriter(outBackupFile)
	defer gzw.Close()
	tw := NewTarWriter(tar.NewWriter(gzw))
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
		podVolumeSnapshotTracker: podvolume.NewTracker(),
		hookTracker:              hook.NewHookTracker(),
		kubernetesBackupper:      kb,
	}
	updateFiles := make(map[string]FileForArchive)
	backedUpGroupResources := map[schema.GroupResource]bool{}

	unstructuredDataUploads := make([]unstructured.Unstructured, 0)

	for i, item := range items {
		log.WithFields(map[string]any{
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

			if item.groupResource == kuberesource.DataUploads {
				unstructuredDataUploads = append(unstructuredDataUploads, unstructured)
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
		backedUpItems := backupRequest.BackedUpItems.Len()
		totalItems := backedUpItems + (len(items) - (i + 1))

		log.WithFields(map[string]any{
			"progress":  "",
			"resource":  item.groupResource.String(),
			"namespace": item.namespace,
			"name":      item.name,
		}).Infof("Updated %d items out of an estimated total of %d (estimate will change throughout the backup finalizer)", backedUpItems, totalItems)
	}

	volumeInfos, err := backupStore.GetBackupVolumeInfos(backupRequest.Backup.Name)
	if err != nil {
		log.WithError(err).Errorf("fail to get the backup VolumeInfos for backup %s", backupRequest.Name)
		return err
	}

	if err := updateVolumeInfos(volumeInfos, unstructuredDataUploads, asyncBIAOperations, log); err != nil {
		log.WithError(err).Errorf("fail to update VolumeInfos for backup %s", backupRequest.Name)
		return err
	}

	if err := putVolumeInfos(backupRequest.Name, volumeInfos, backupStore); err != nil {
		log.WithError(err).Errorf("fail to put the VolumeInfos for backup %s", backupRequest.Name)
		return err
	}

	// write new tar archive replacing files in original with content updateFiles for matches
	if err := buildFinalTarball(tr, tw, updateFiles); err != nil {
		log.Errorf("Error building final tarball: %s", err.Error())
		return err
	}

	log.WithField("progress", "").Infof("Updated a total of %d items", backupRequest.BackedUpItems.Len())

	return nil
}

func buildFinalTarball(tr *tar.Reader, tw tarWriter, updateFiles map[string]FileForArchive) error {
	tw.Lock()
	defer tw.Unlock()
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

type tarWriter struct {
	*tar.Writer
	*sync.Mutex
}

func NewTarWriter(writer *tar.Writer) tarWriter {
	return tarWriter{
		Writer: writer,
		Mutex:  &sync.Mutex{},
	}
}

// updateVolumeInfos update the VolumeInfos according to the AsyncOperations
func updateVolumeInfos(
	volumeInfos []*volume.BackupVolumeInfo,
	unstructuredItems []unstructured.Unstructured,
	operations []*itemoperation.BackupOperation,
	log logrus.FieldLogger,
) error {
	for _, unstructured := range unstructuredItems {
		var dataUpload velerov2alpha1.DataUpload
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured.UnstructuredContent(), &dataUpload)
		if err != nil {
			log.WithError(err).Errorf("fail to convert DataUpload: %s/%s",
				unstructured.GetNamespace(), unstructured.GetName())
			return err
		}

		for index := range volumeInfos {
			if volumeInfos[index].PVCName == dataUpload.Spec.SourcePVC &&
				volumeInfos[index].PVCNamespace == dataUpload.Spec.SourceNamespace &&
				volumeInfos[index].SnapshotDataMovementInfo != nil {
				if dataUpload.Status.CompletionTimestamp != nil {
					volumeInfos[index].CompletionTimestamp = dataUpload.Status.CompletionTimestamp
				}
				volumeInfos[index].SnapshotDataMovementInfo.SnapshotHandle = dataUpload.Status.SnapshotID
				volumeInfos[index].SnapshotDataMovementInfo.RetainedSnapshot = dataUpload.Spec.CSISnapshot.VolumeSnapshot
				volumeInfos[index].SnapshotDataMovementInfo.Size = dataUpload.Status.Progress.TotalBytes
				volumeInfos[index].SnapshotDataMovementInfo.IncrementalSize = dataUpload.Status.IncrementalBytes
				volumeInfos[index].SnapshotDataMovementInfo.Phase = dataUpload.Status.Phase

				if dataUpload.Status.Phase == velerov2alpha1.DataUploadPhaseCompleted {
					volumeInfos[index].Result = volume.VolumeResultSucceeded
				} else {
					volumeInfos[index].Result = volume.VolumeResultFailed
				}
			}
		}
	}

	// Update CSI snapshot VolumeInfo's CompletionTimestamp by the operation update time.
	for volumeIndex := range volumeInfos {
		if volumeInfos[volumeIndex].BackupMethod == volume.CSISnapshot &&
			volumeInfos[volumeIndex].CSISnapshotInfo != nil {
			for opIndex := range operations {
				if volumeInfos[volumeIndex].CSISnapshotInfo.OperationID == operations[opIndex].Spec.OperationID {
					// The VolumeSnapshot and VolumeSnapshotContent don't have a completion timestamp,
					// so use the operation.Status.Updated as the alternative. It is not the exact time
					// when the snapshot turns ready, but the operation controller periodically watch the
					// VSC and VS status. When the controller finds they reach to the ReadyToUse state,
					// The operation.Status.Updated is set as the found time.
					volumeInfos[volumeIndex].CompletionTimestamp = operations[opIndex].Status.Updated

					// Set Succeeded to true when the operation has no error.
					if operations[opIndex].Status.Error == "" {
						volumeInfos[volumeIndex].Result = volume.VolumeResultSucceeded
					} else {
						volumeInfos[volumeIndex].Result = volume.VolumeResultFailed
					}
				}
			}
		}
	}

	return nil
}

func putVolumeInfos(
	backupName string,
	volumeInfos []*volume.BackupVolumeInfo,
	backupStore persistence.BackupStore,
) error {
	backupVolumeInfoBuf := new(bytes.Buffer)
	gzw := gzip.NewWriter(backupVolumeInfoBuf)
	defer gzw.Close()

	if err := json.NewEncoder(gzw).Encode(volumeInfos); err != nil {
		return errors.Wrap(err, "error encoding restore results to JSON")
	}

	if err := gzw.Close(); err != nil {
		return errors.Wrap(err, "error closing gzip writer")
	}

	return backupStore.PutBackupVolumeInfos(backupName, backupVolumeInfoBuf)
}
