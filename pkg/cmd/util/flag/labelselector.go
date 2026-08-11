/*
Copyright 2017 the Velero contributors.

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

package flag

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LabelSelector is a Cobra-compatible wrapper for defining
// a Kubernetes label-selector flag.
type LabelSelector struct {
	LabelSelector *metav1.LabelSelector
}

// String returns a string representation of the label
// selector flag.
func (ls *LabelSelector) String() string {
	return metav1.FormatLabelSelector(ls.LabelSelector)
}

// Set parses the provided string and assigns the result
// to the label-selector receiver. It returns an error if
// the string is not parseable.
func (ls *LabelSelector) Set(s string) error {
	parsed, err := parseToLabelSelector(s)
	if err != nil {
		return err
	}
	ls.LabelSelector = parsed
	return nil
}

// Type returns a string representation of the
// LabelSelector type.
func (ls *LabelSelector) Type() string {
	return "labelSelector"
}
