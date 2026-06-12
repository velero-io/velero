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

package podvolume

import (
	"context"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util"
)

// PVCPodCache provides a cached mapping from PVC to the pods that use it.
// This cache is built once per backup to avoid repeated pod listings which
// cause O(N*M) performance issues when there are many PVCs and pods.
type PVCPodCache struct {
	mu sync.RWMutex
	// cache maps namespace -> pvcName -> []Pod
	cache map[string]map[string][]corev1api.Pod
	// built indicates whether the cache has been populated
	built bool
}

// NewPVCPodCache creates a new empty PVC to Pod cache.
func NewPVCPodCache() *PVCPodCache {
	return &PVCPodCache{
		cache: make(map[string]map[string][]corev1api.Pod),
		built: false,
	}
}

// BuildCacheForNamespaces builds the cache by listing pods once per namespace.
// This is much more efficient than listing pods for each PVC lookup.
func (c *PVCPodCache) BuildCacheForNamespaces(
	ctx context.Context,
	namespaces []string,
	crClient crclient.Client,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ns := range namespaces {
		podList := new(corev1api.PodList)
		if err := crClient.List(
			ctx,
			podList,
			&crclient.ListOptions{Namespace: ns},
		); err != nil {
			return errors.Wrapf(err, "failed to list pods in namespace %s", ns)
		}

		if c.cache[ns] == nil {
			c.cache[ns] = make(map[string][]corev1api.Pod)
		}

		// Build mapping from PVC name to pods
		for i := range podList.Items {
			pod := podList.Items[i]
			for _, v := range pod.Spec.Volumes {
				if v.PersistentVolumeClaim != nil {
					pvcName := v.PersistentVolumeClaim.ClaimName
					c.cache[ns][pvcName] = append(c.cache[ns][pvcName], pod)
				}
			}
		}
	}

	c.built = true
	return nil
}

// GetPodsUsingPVC retrieves pods using a specific PVC from the cache.
// Returns nil slice if the PVC is not found in the cache.
func (c *PVCPodCache) GetPodsUsingPVC(namespace, pvcName string) []corev1api.Pod {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if nsPods, ok := c.cache[namespace]; ok {
		if pods, ok := nsPods[pvcName]; ok {
			// Return a copy to avoid race conditions
			result := make([]corev1api.Pod, len(pods))
			copy(result, pods)
			return result
		}
	}
	return nil
}

// IsBuilt returns true if the cache has been built.
func (c *PVCPodCache) IsBuilt() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.built
}

// IsNamespaceBuilt returns true if the cache has been built for the given namespace.
func (c *PVCPodCache) IsNamespaceBuilt(namespace string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.cache[namespace]
	return ok
}

// BuildCacheForNamespace builds the cache for a single namespace lazily.
// This is used by plugins where namespaces are encountered one at a time.
// If the namespace is already cached, this is a no-op.
func (c *PVCPodCache) BuildCacheForNamespace(
	ctx context.Context,
	namespace string,
	crClient crclient.Client,
) error {
	// Check if already built (read lock first for performance)
	c.mu.RLock()
	if _, ok := c.cache[namespace]; ok {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	// Need to build - acquire write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if _, ok := c.cache[namespace]; ok {
		return nil
	}

	podList := new(corev1api.PodList)
	if err := crClient.List(
		ctx,
		podList,
		&crclient.ListOptions{Namespace: namespace},
	); err != nil {
		return errors.Wrapf(err, "failed to list pods in namespace %s", namespace)
	}

	c.cache[namespace] = make(map[string][]corev1api.Pod)

	// Build mapping from PVC name to pods
	for i := range podList.Items {
		pod := podList.Items[i]
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				pvcName := v.PersistentVolumeClaim.ClaimName
				c.cache[namespace][pvcName] = append(c.cache[namespace][pvcName], pod)
			}
		}
	}

	// Mark as built for GetPodsUsingPVCWithCache fallback logic
	c.built = true
	return nil
}

// GetVolumesByPod returns a list of volume names to backup for the provided pod.
func GetVolumesByPod(pod *corev1api.Pod, defaultVolumesToFsBackup, backupExcludePVC bool, volsToProcessByLegacyApproach []string) ([]string, []string) {
	// tracks the volumes that have been explicitly opted out of backup via the annotation in the pod
	optedOutVolumes := make([]string, 0)

	if !defaultVolumesToFsBackup {
		return GetVolumesToBackup(pod), optedOutVolumes
	}

	volsToExclude := GetVolumesToExclude(pod)
	podVolumes := []string{}
	// Identify volume to process
	// For normal case all the pod volume will be processed
	// For case when volsToProcessByLegacyApproach is non-empty then only those volume will be processed
	volsToProcess := GetVolumesToProcess(pod.Spec.Volumes, volsToProcessByLegacyApproach)
	for _, pv := range volsToProcess {
		// cannot backup hostpath volumes as they are not mounted into /var/lib/kubelet/pods
		// and therefore not accessible to the node agent daemon set.
		if pv.HostPath != nil {
			continue
		}
		// don't backup volumes mounting secrets. Secrets will be backed up separately.
		if pv.Secret != nil {
			continue
		}
		// don't backup volumes mounting ConfigMaps. ConfigMaps will be backed up separately.
		if pv.ConfigMap != nil {
			continue
		}
		// don't backup volumes mounted as projected volumes, all data in those come from kube state.
		if pv.Projected != nil {
			continue
		}
		// don't backup DownwardAPI volumes, all data in those come from kube state.
		if pv.DownwardAPI != nil {
			continue
		}
		if pv.PersistentVolumeClaim != nil && backupExcludePVC {
			continue
		}
		// don't backup volumes that are included in the exclude list.
		if util.Contains(volsToExclude, pv.Name) {
			optedOutVolumes = append(optedOutVolumes, pv.Name)
			continue
		}
		// don't include volumes that mount the default service account token.
		if strings.HasPrefix(pv.Name, "default-token") {
			continue
		}
		podVolumes = append(podVolumes, pv.Name)
	}
	return podVolumes, optedOutVolumes
}

// GetVolumesToBackup returns a list of volume names to backup for
// the provided pod.
// Deprecated: Use GetVolumesByPod instead.
func GetVolumesToBackup(obj metav1.Object) []string {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return nil
	}

	backupsValue := annotations[velerov1api.VolumesToBackupAnnotation]
	if backupsValue == "" {
		return nil
	}

	return strings.Split(backupsValue, ",")
}

func GetVolumesToExclude(obj metav1.Object) []string {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return nil
	}

	return strings.Split(annotations[velerov1api.VolumesToExcludeAnnotation], ",")
}

// IsPVCDefaultToFSBackupWithCache checks if a PVC should default to fs-backup based on pod annotations.
// If cache is nil or not built, it falls back to listing pods directly.
// Note: In the main backup path, the cache is always built (via NewVolumeHelperImplWithNamespaces),
// so the fallback is only used by plugins that don't need cache optimization.
func IsPVCDefaultToFSBackupWithCache(
	pvcNamespace, pvcName string,
	crClient crclient.Client,
	defaultVolumesToFsBackup bool,
	cache *PVCPodCache,
) (bool, error) {
	var pods []corev1api.Pod
	var err error

	// Use cache if available, otherwise fall back to direct lookup
	if cache != nil && cache.IsBuilt() {
		pods = cache.GetPodsUsingPVC(pvcNamespace, pvcName)
	} else {
		pods, err = getPodsUsingPVCDirect(pvcNamespace, pvcName, crClient)
		if err != nil {
			return false, errors.WithStack(err)
		}
	}

	return checkPodsForFSBackup(pods, pvcName, defaultVolumesToFsBackup)
}

// checkPodsForFSBackup is a helper function that checks if any pod using the PVC
// has the volume selected for fs-backup.
func checkPodsForFSBackup(pods []corev1api.Pod, pvcName string, defaultVolumesToFsBackup bool) (bool, error) {
	for index := range pods {
		vols, _ := GetVolumesByPod(&pods[index], defaultVolumesToFsBackup, false, []string{})
		if len(vols) > 0 {
			volName, err := getPodVolumeNameForPVC(pods[index], pvcName)
			if err != nil {
				return false, err
			}
			if util.Contains(vols, volName) {
				return true, nil
			}
		}
	}

	return false, nil
}

func getPodVolumeNameForPVC(pod corev1api.Pod, pvcName string) (string, error) {
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvcName {
			return v.Name, nil
		}
	}
	return "", errors.Errorf("Pod %s/%s does not use PVC %s/%s", pod.Namespace, pod.Name, pod.Namespace, pvcName)
}

// GetPodsUsingPVCWithCache returns all pods that use the specified PVC.
// If cache is available and built, it uses the cache for O(1) lookup.
// Otherwise, it falls back to listing pods directly.
// Note: In the main backup path, the cache is always built (via NewVolumeHelperImplWithNamespaces),
// so the fallback is only used by plugins that don't need cache optimization.
func GetPodsUsingPVCWithCache(
	pvcNamespace, pvcName string,
	crClient crclient.Client,
	cache *PVCPodCache,
) ([]corev1api.Pod, error) {
	// Use cache if available
	if cache != nil && cache.IsBuilt() {
		pods := cache.GetPodsUsingPVC(pvcNamespace, pvcName)
		if pods == nil {
			return []corev1api.Pod{}, nil
		}
		return pods, nil
	}

	// Fall back to direct lookup (for plugins without cache)
	return getPodsUsingPVCDirect(pvcNamespace, pvcName, crClient)
}

// getPodsUsingPVCDirect returns all pods in the given namespace that use the specified PVC.
// This is an internal function that lists all pods in the namespace and filters them.
func getPodsUsingPVCDirect(
	pvcNamespace, pvcName string,
	crClient crclient.Client,
) ([]corev1api.Pod, error) {
	podsUsingPVC := []corev1api.Pod{}
	podList := new(corev1api.PodList)
	if err := crClient.List(
		context.TODO(),
		podList,
		&crclient.ListOptions{Namespace: pvcNamespace},
	); err != nil {
		return nil, err
	}

	for _, p := range podList.Items {
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvcName {
				podsUsingPVC = append(podsUsingPVC, p)
			}
		}
	}

	return podsUsingPVC, nil
}

func GetVolumesToProcess(volumes []corev1api.Volume, volsToProcessByLegacyApproach []string) []corev1api.Volume {
	volsToProcess := make([]corev1api.Volume, 0)

	// return empty list when no volumes associated with pod
	if len(volumes) == 0 {
		return volsToProcess
	}

	// legacy approach as a fallback option case
	if len(volsToProcessByLegacyApproach) > 0 {
		for _, vol := range volumes {
			// don't process volumes that are already matched for supported action in volume policy approach
			if !util.Contains(volsToProcessByLegacyApproach, vol.Name) {
				continue
			}

			// add volume that is not processed in volume policy approach
			volsToProcess = append(volsToProcess, vol)
		}

		return volsToProcess
	}
	// normal case return the list as in
	return volumes
}
