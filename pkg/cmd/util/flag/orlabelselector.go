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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OrLabelSelector is a Cobra-compatible wrapper for defining
// a Kubernetes or-label-selector flag.
type OrLabelSelector struct {
	OrLabelSelectors []*metav1.LabelSelector
}

// String returns a string representation of the or-label
// selector flag.
func (ls *OrLabelSelector) String() string {
	orLabels := []string{}
	for _, v := range ls.OrLabelSelectors {
		orLabels = append(orLabels, metav1.FormatLabelSelector(v))
	}
	return strings.Join(orLabels, " or ")
}

// Set parses the provided string and assigns the result
// to the or-label-selector receiver. It returns an error if
// the string is not parseable.
func (ls *OrLabelSelector) Set(s string) error {
	orItems := strings.Split(s, " or ")
	ls.OrLabelSelectors = make([]*metav1.LabelSelector, 0)
	for _, orItem := range orItems {
		parsed, err := parseToLabelSelector(orItem)
		if err != nil {
			return err
		}
		ls.OrLabelSelectors = append(ls.OrLabelSelectors, parsed)
	}
	return nil
}

// Type returns a string representation of the
// OrLabelSelector type.
func (ls *OrLabelSelector) Type() string {
	return "orLabelSelector"
}
