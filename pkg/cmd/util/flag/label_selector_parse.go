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

package flag

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// parseToLabelSelector parses a Kubernetes label selector string into a
// metav1.LabelSelector. It mirrors metav1.ParseToLabelSelector, but also
// accepts the "!=" operator (selection.NotEquals) by mapping it to NotIn,
// which is how kubectl and labels.Parse treat inequality.
func parseToLabelSelector(selector string) (*metav1.LabelSelector, error) {
	reqs, err := labels.ParseToRequirements(selector)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse the selector string %q: %v", selector, err)
	}

	labelSelector := &metav1.LabelSelector{
		MatchLabels:      map[string]string{},
		MatchExpressions: []metav1.LabelSelectorRequirement{},
	}
	for _, req := range reqs {
		var op metav1.LabelSelectorOperator
		switch req.Operator() {
		case selection.Equals, selection.DoubleEquals:
			vals := req.Values()
			if vals.Len() != 1 {
				return nil, fmt.Errorf("equals operator must have exactly one value")
			}
			val, ok := vals.PopAny()
			if !ok {
				return nil, fmt.Errorf("equals operator has exactly one value but it cannot be retrieved")
			}
			labelSelector.MatchLabels[req.Key()] = val
			continue
		case selection.In:
			op = metav1.LabelSelectorOpIn
		case selection.NotIn, selection.NotEquals:
			// "!=" is valid for labels.Parse / kubectl but not stored on
			// metav1.LabelSelector; NotIn with the same values is equivalent.
			op = metav1.LabelSelectorOpNotIn
		case selection.Exists:
			op = metav1.LabelSelectorOpExists
		case selection.DoesNotExist:
			op = metav1.LabelSelectorOpDoesNotExist
		case selection.GreaterThan, selection.LessThan:
			return nil, fmt.Errorf("%q isn't supported in label selectors", req.Operator())
		default:
			return nil, fmt.Errorf("%q is not a valid label selector operator", req.Operator())
		}
		labelSelector.MatchExpressions = append(labelSelector.MatchExpressions, metav1.LabelSelectorRequirement{
			Key:      req.Key(),
			Operator: op,
			Values:   req.Values().List(),
		})
	}
	return labelSelector, nil
}
