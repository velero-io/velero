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

package restore

import (
	"context"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/archive"
	"github.com/vmware-tanzu/velero/pkg/client"
)

// ChosenGroupVersion is the API Group version that was selected to restore
// from potentially multiple backed up version enabled by the feature flag
// APIGroupVersionsFeatureFlag
type ChosenGroupVersion struct {
	Group   string
	Version string
	Dir     string
}

// chooseAPIVersionsToRestore will choose a version to restore based on a user-
// provided config map prioritization or our version prioritization.
func (ctx *restoreContext) chooseAPIVersionsToRestore() error {
	sourceGVs, targetGVs, userGVs, err := ctx.gatherSourceTargetUserGroupVersions()
	if err != nil {
		return err
	}

OUTER:
	for rg, sg := range sourceGVs {
		// Default to the source preferred version if no other common version
		// can be found.
		cgv := ChosenGroupVersion{
			Group:   sg.Name,
			Version: sg.PreferredVersion.Version,
			Dir:     sg.PreferredVersion.Version + velerov1api.PreferredVersionDir,
		}

		tg := findAPIGroup(targetGVs, sg.Name)
		if len(tg.Versions) == 0 {
			ctx.chosenGrpVersToRestore[rg] = cgv
			ctx.log.Debugf("Chose %s/%s API group version to restore", cgv.Group, cgv.Version)
			continue
		}

		// Priority 0: User Priority Version
		if userGVs != nil {
			uv := findSupportedUserVersion(userGVs[rg].Versions, tg.Versions, sg.Versions)
			if uv != "" {
				cgv.Version = uv
				cgv.Dir = uv

				if uv == sg.PreferredVersion.Version {
					cgv.Dir += velerov1api.PreferredVersionDir
				}

				ctx.chosenGrpVersToRestore[rg] = cgv
				ctx.log.Debugf("APIGroupVersionsFeatureFlag Priority 0: User defined API group version %s chosen for %s", uv, rg)
				continue
			}

			ctx.log.Infof("Cannot find user defined version in both the cluster and backup cluster. Ignoring version %s for %s", uv, rg)
		}

		// Priority 1: Target Cluster Preferred Version
		if versionsContain(sg.Versions, tg.PreferredVersion.Version) {
			cgv.Version = tg.PreferredVersion.Version
			cgv.Dir = tg.PreferredVersion.Version

			if tg.PreferredVersion.Version == sg.PreferredVersion.Version {
				cgv.Dir += velerov1api.PreferredVersionDir
			}

			ctx.chosenGrpVersToRestore[rg] = cgv
			ctx.log.Debugf(
				"APIGroupVersionsFeatureFlag Priority 1: Cluster preferred API group version %s found in backup for %s",
				tg.PreferredVersion.Version,
				rg,
			)
			continue
		}
		ctx.log.Infof("Cannot find cluster preferred API group version in backup. Ignoring version %s for %s", tg.PreferredVersion.Version, rg)

		// Priority 2: Source Cluster Preferred Version
		if versionsContain(tg.Versions, sg.PreferredVersion.Version) {
			cgv.Version = sg.PreferredVersion.Version
			cgv.Dir = cgv.Version + velerov1api.PreferredVersionDir

			ctx.chosenGrpVersToRestore[rg] = cgv
			ctx.log.Debugf(
				"APIGroupVersionsFeatureFlag Priority 2: Cluster preferred API group version not found in backup. Using backup preferred version %s for %s",
				sg.PreferredVersion.Version,
				rg,
			)
			continue
		}
		ctx.log.Infof("Cannot find backup preferred API group version in cluster. Ignoring version %s for %s", sg.PreferredVersion.Version, rg)

		// Priority 3: The Common Supported Version with the Highest Kubernetes Version Priority
		for _, tv := range tg.Versions[1:] {
			if versionsContain(sg.Versions[1:], tv.Version) {
				cgv.Version = tv.Version
				cgv.Dir = tv.Version

				ctx.chosenGrpVersToRestore[rg] = cgv
				ctx.log.Debugf(
					"APIGroupVersionsFeatureFlag Priority 3: Common supported but not preferred API group version %s chosen for %s",
					tv.Version,
					rg,
				)
				continue OUTER
			}
		}
		ctx.log.Infof("Cannot find non-preferred a common supported API group version. Using %s (default behavior without feature flag) for %s", sg.PreferredVersion.Version, rg)

		// Use default group version.
		ctx.chosenGrpVersToRestore[rg] = cgv
		ctx.log.Debugf(
			"APIGroupVersionsFeatureFlag: Unable to find supported priority API group version. Using backup preferred version %s for %s (default behavior without feature flag).",
			tg.PreferredVersion.Version,
			rg,
		)
	}

	return nil
}

// gatherSourceTargetUserGroupVersions collects the source, target, and user priority versions.
func (ctx *restoreContext) gatherSourceTargetUserGroupVersions() (
	map[string]metav1.APIGroup,
	[]metav1.APIGroup,
	map[string]metav1.APIGroup,
	error,
) {
	sourceRGVersions, err := archive.NewParser(ctx.log, ctx.fileSystem).ParseGroupVersions(ctx.restoreDir)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing versions from directory names")
	}

	// Sort the versions in the APIGroups in sourceRGVersions map values.
	for _, src := range sourceRGVersions {
		k8sPrioritySort(src.Versions)
	}

	targetGroupVersions := ctx.discoveryHelper.APIGroups()

	// Sort the versions in the APIGroups slice in targetGroupVersions.
	for _, target := range targetGroupVersions {
		k8sPrioritySort(target.Versions)
	}

	// Get the user-provided enableapigroupversion config map.
	cm, err := userPriorityConfigMap()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "retrieving enableapigroupversion config map")
	}

	// Read user-defined version priorities from config map.
	userRGVPriorities := userResourceGroupVersionPriorities(ctx, cm)

	return sourceRGVersions, targetGroupVersions, userRGVPriorities, nil
}

// k8sPrioritySort sorts slices using Kubernetes' version prioritization.
func k8sPrioritySort(gvs []metav1.GroupVersionForDiscovery) {
	sort.SliceStable(gvs, func(i, j int) bool {
		return version.CompareKubeAwareVersionStrings(gvs[i].Version, gvs[j].Version) > 0
	})
}

// userResourceGroupVersionPriorities retrieves a user-provided config map and
// extracts the user priority versions for each resource.
func userResourceGroupVersionPriorities(ctx *restoreContext, cm *corev1api.ConfigMap) map[string]metav1.APIGroup {
	if cm == nil {
		ctx.log.Debugf("No enableapigroupversion config map found in velero namespace. Using pre-defined priorities.")
		return nil
	}

	priorities := parseUserPriorities(ctx, cm.Data["restoreResourcesVersionPriority"])
	if len(priorities) == 0 {
		ctx.log.Debugf("No valid user version priorities found in enableapigroupversion config map. Using pre-defined priorities.")
		return nil
	}

	return priorities
}

func userPriorityConfigMap() (*corev1api.ConfigMap, error) {
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, errors.Wrap(err, "reading client config file")
	}

	fc := client.NewFactory("APIGroupVersionsRestore", cfg)

	kc, err := fc.KubeClient()
	if err != nil {
		return nil, errors.Wrap(err, "getting Kube client")
	}

	cm, err := kc.CoreV1().ConfigMaps(fc.Namespace()).Get(
		context.Background(),
		"enableapigroupversions",
		metav1.GetOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}

		return nil, errors.Wrap(err, "getting enableapigroupversions config map from velero namespace")
	}

	return cm, nil
}

func parseUserPriorities(ctx *restoreContext, prioritiesData string) map[string]metav1.APIGroup {
	userPriorities := make(map[string]metav1.APIGroup)

	// The user priorities will be in a string of the form
	// rockbands.music.example.io=v2beta1,v2beta2\n
	// orchestras.music.example.io=v2,v3alpha1\n
	// subscriptions.operators.coreos.com=v2,v1

	lines := strings.Split(prioritiesData, "\n")
	lines = formatUserPriorities(lines)

	for _, line := range lines {
		err := validateUserPriority(line)

		if err == nil {
			rgvs := strings.SplitN(line, "=", 2)
			rg := rgvs[0]       // rockbands.music.example.io
			versions := rgvs[1] // v2beta1,v2beta2

			vers := strings.Split(versions, ",")

			userPriorities[rg] = metav1.APIGroup{
				Versions: versionsToGroupVersionForDiscovery(vers),
			}
		} else {
			ctx.log.Debugf("Unable to validate user priority versions %q due to %v", line, err)
		}
	}

	return userPriorities
}

// formatUserPriorities removes extra white spaces that cause validation to fail.
func formatUserPriorities(lines []string) []string {
	trimmed := []string{}

	for _, line := range lines {
		temp := strings.ReplaceAll(line, " ", "")

		if len(temp) > 0 {
			trimmed = append(trimmed, temp)
		}
	}

	return trimmed
}

func validateUserPriority(line string) error {
	if strings.Count(line, "=") != 1 {
		return errors.New("line must have one and only one equal sign")
	}

	pair := strings.Split(line, "=")
	if len(pair[0]) < 1 || len(pair[1]) < 1 {
		return errors.New("line must contain at least one character before and after equal sign")
	}

	// Line must not contain any spaces
	if strings.Count(line, " ") > 0 {
		return errors.New("line must not contain any spaces")
	}

	return nil
}

// versionsToGroupVersionForDiscovery converts version strings into a Kubernetes format
// for group versions.
func versionsToGroupVersionForDiscovery(vs []string) []metav1.GroupVersionForDiscovery {
	gvs := make([]metav1.GroupVersionForDiscovery, len(vs))

	for i, v := range vs {
		gvs[i] = metav1.GroupVersionForDiscovery{
			Version: v,
		}
	}

	return gvs
}

// findAPIGroup looks for an API Group by a group name.
func findAPIGroup(groups []metav1.APIGroup, name string) metav1.APIGroup {
	for _, g := range groups {
		if g.Name == name {
			return g
		}
	}

	return metav1.APIGroup{}
}

// findSupportedUserVersion finds the first user priority version that both source
// and target support.
func findSupportedUserVersion(userGVs, targetGVs, sourceGVs []metav1.GroupVersionForDiscovery) string {
	for _, ug := range userGVs {
		if versionsContain(targetGVs, ug.Version) && versionsContain(sourceGVs, ug.Version) {
			return ug.Version
		}
	}

	return ""
}

// versionsContain will check if a version can be found in a slice of versions.
func versionsContain(list []metav1.GroupVersionForDiscovery, version string) bool {
	for _, v := range list {
		if v.Version == version {
			return true
		}
	}

	return false
}
