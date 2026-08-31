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
	"strings"
)

func (r *ResourceModifierRule) Validate() error {
	if err := r.Conditions.Validate(); err != nil {
		return err
	}

	count := 0
	for _, size := range []int{
		len(r.Patches),
		len(r.MergePatches),
		len(r.StrategicPatches),
	} {
		if size != 0 {
			count++
		}
		if count >= 2 {
			return fmt.Errorf("only one of patches, mergePatches, strategicPatches can be specified")
		}
	}

	for _, patch := range r.Patches {
		if err := patch.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p *ResourceModifiers) Validate() error {
	if !strings.EqualFold(p.Version, ResourceModifierSupportedVersionV1) {
		return fmt.Errorf("unsupported resource modifier version %s", p.Version)
	}
	if len(p.ResourceModifierRules) == 0 {
		return fmt.Errorf("resource modifier rules cannot be empty")
	}
	for _, rule := range p.ResourceModifierRules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (p *JSONPatch) Validate() error {
	if p.Operation == "" {
		return fmt.Errorf("operation cannot be empty")
	}
	if operation := strings.ToLower(p.Operation); operation != "add" && operation != "remove" && operation != "replace" && operation != "test" && operation != "move" && operation != "copy" {
		return fmt.Errorf("unsupported operation %s", p.Operation)
	}
	if p.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	return nil
}

func (c *Conditions) Validate() error {
	if c.GroupResource == "" {
		return fmt.Errorf("groupResource cannot be empty")
	}
	return nil
}
