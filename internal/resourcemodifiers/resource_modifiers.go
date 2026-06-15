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
package resourcemodifiers

import (
	"fmt"
	"regexp"

	"github.com/cockroachdb/errors"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/gobwas/glob"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/vmware-tanzu/velero/pkg/util/collections"
)

const (
	ConfigmapRefType                   = "configmap"
	ResourceModifierSupportedVersionV1 = "v1"
)

type MatchRule struct {
	Path  string `json:"path,omitempty"`
	Value string `json:"value,omitempty"`
}

type Conditions struct {
	Namespaces        []string              `json:"namespaces,omitempty"`
	GroupResource     string                `json:"groupResource"`
	ResourceNameRegex string                `json:"resourceNameRegex,omitempty"`
	LabelSelector     *metav1.LabelSelector `json:"labelSelector,omitempty"`
	Matches           []MatchRule           `json:"matches,omitempty"`
}

type ResourceModifierRule struct {
	Conditions       Conditions            `json:"conditions"`
	Patches          []JSONPatch           `json:"patches,omitempty"`
	MergePatches     []JSONMergePatch      `json:"mergePatches,omitempty"`
	StrategicPatches []StrategicMergePatch `json:"strategicPatches,omitempty"`
}

type ResourceModifiers struct {
	Version               string                 `json:"version"`
	ResourceModifierRules []ResourceModifierRule `json:"resourceModifierRules"`
}

func GetResourceModifiersFromConfig(cm *corev1api.ConfigMap) (*ResourceModifiers, error) {
	if cm == nil {
		return nil, fmt.Errorf("could not parse config from nil configmap")
	}
	if len(cm.Data) != 1 {
		return nil, fmt.Errorf("illegal resource modifiers %s/%s configmap", cm.Namespace, cm.Name)
	}

	var yamlData string
	for _, v := range cm.Data {
		yamlData = v
	}

	resModifiers, err := unmarshalResourceModifiers([]byte(yamlData))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resModifiers, nil
}

func (p *ResourceModifiers) ApplyResourceModifierRules(obj *unstructured.Unstructured, groupResource string, scheme *runtime.Scheme, log logrus.FieldLogger) []error {
	var errs []error
	origin := obj
	// If there are more than one rules, we need to keep the original object for condition matching
	if len(p.ResourceModifierRules) > 1 {
		origin = obj.DeepCopy()
	}
	for _, rule := range p.ResourceModifierRules {
		matched, err := rule.match(origin, groupResource, log)
		if err != nil {
			errs = append(errs, err)
			continue
		} else if !matched {
			continue
		}

		log.Infof("Applying resource modifier patch on %s/%s", origin.GetNamespace(), origin.GetName())
		err = rule.applyPatch(obj, scheme, log)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (r *ResourceModifierRule) match(obj *unstructured.Unstructured, groupResource string, log logrus.FieldLogger) (bool, error) {
	ns := obj.GetNamespace()
	if ns != "" {
		namespaceInclusion := collections.NewIncludesExcludes().Includes(r.Conditions.Namespaces...)
		if !namespaceInclusion.ShouldInclude(ns) {
			return false, nil
		}
	}

	g, err := glob.Compile(r.Conditions.GroupResource, '.')
	if err != nil {
		log.Errorf("Bad glob pattern of groupResource in condition, groupResource: %s, err: %s", r.Conditions.GroupResource, err)
		return false, err
	}

	if !g.Match(groupResource) {
		return false, nil
	}

	if r.Conditions.ResourceNameRegex != "" {
		match, err := regexp.MatchString(r.Conditions.ResourceNameRegex, obj.GetName())
		if err != nil {
			return false, errors.Errorf("error in matching regex %s", err.Error())
		}
		if !match {
			return false, nil
		}
	}

	if r.Conditions.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(r.Conditions.LabelSelector)
		if err != nil {
			return false, errors.Errorf("error in creating label selector %s", err.Error())
		}
		if !selector.Matches(labels.Set(obj.GetLabels())) {
			return false, nil
		}
	}

	match, err := matchConditions(obj, r.Conditions.Matches, log)
	if err != nil {
		return false, err
	} else if !match {
		log.Info("Conditions do not match, skip it")
		return false, nil
	}

	return true, nil
}

func matchConditions(u *unstructured.Unstructured, rules []MatchRule, _ logrus.FieldLogger) (bool, error) {
	if len(rules) == 0 {
		return true, nil
	}

	var fixed []JSONPatch
	for _, rule := range rules {
		if rule.Path == "" {
			return false, fmt.Errorf("path is required for match rule")
		}

		fixed = append(fixed, JSONPatch{
			Operation: "test",
			Path:      rule.Path,
			Value:     rule.Value,
		})
	}

	p := &JSONPatcher{patches: fixed}
	_, err := p.applyPatch(u)
	if err != nil {
		if errors.Is(err, jsonpatch.ErrTestFailed) || errors.Is(err, jsonpatch.ErrMissing) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func unmarshalResourceModifiers(yamlData []byte) (*ResourceModifiers, error) {
	resModifiers := &ResourceModifiers{}
	err := yaml.UnmarshalStrict(yamlData, resModifiers)
	if err != nil {
		return nil, fmt.Errorf("failed to decode yaml data into resource modifiers, err: %s", err)
	}
	return resModifiers, nil
}

type patcher interface {
	Patch(u *unstructured.Unstructured, logger logrus.FieldLogger) (*unstructured.Unstructured, error)
}

func (r *ResourceModifierRule) applyPatch(u *unstructured.Unstructured, scheme *runtime.Scheme, logger logrus.FieldLogger) error {
	var p patcher
	if len(r.Patches) > 0 {
		p = &JSONPatcher{patches: r.Patches}
	} else if len(r.MergePatches) > 0 {
		p = &JSONMergePatcher{patches: r.MergePatches}
	} else if len(r.StrategicPatches) > 0 {
		p = &StrategicMergePatcher{patches: r.StrategicPatches, scheme: scheme}
	} else {
		return fmt.Errorf("no patch data found")
	}

	updated, err := p.Patch(u, logger)
	if err != nil {
		return fmt.Errorf("error in applying patch %s", err)
	}

	u.SetUnstructuredContent(updated.Object)
	return nil
}
