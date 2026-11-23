/*
Copyright 2019 the Velero contributors.

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

package label

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// GetValidName converts an input string to valid Kubernetes label string in accordance to rfc1035 DNS Label spec
// (https://github.com/kubernetes/community/blob/master/contributors/design-proposals/architecture/identifiers.md)
// Length of the label is adjusted basis the DNS1035LabelMaxLength (defined at k8s.io/apimachinery/pkg/util/validation)
// If length exceeds, we trim the label name to contain only max allowed characters
// Additionally, the last 6 characters of the label name are replaced by the first 6 characters of the sha256 of original label
func GetValidName(label string) string {
	if len(label) <= validation.DNS1035LabelMaxLength {
		return label
	}

	sha := sha256.Sum256([]byte(label))
	strSha := hex.EncodeToString(sha[:])
	charsFromLabel := validation.DNS1035LabelMaxLength - 6
	if charsFromLabel < 0 {
		// Derive the label name from sha hash in case the DNS1035LabelMaxLength is less than 6
		return string(strSha[validation.DNS1035LabelMaxLength])
	}

	return label[:charsFromLabel] + strSha[:6]
}

// ReturnNameOrHash returns the original name if it is within the DNS1035LabelMaxLength limit,
// otherwise it returns the sha3 Sum224 hash(length is 56) of the name.
func ReturnNameOrHash(name string) string {
	if len(name) <= validation.DNS1035LabelMaxLength {
		return name
	}

	hash := sha3.Sum224([]byte(name))
	return hex.EncodeToString(hash[:])
}

// NewSelectorForBackup returns a Selector based on the backup name.
// This is useful for interacting with Listers that need a Selector.
func NewSelectorForBackup(name string) labels.Selector {
	return labels.SelectorFromSet(map[string]string{velerov1api.BackupNameLabel: GetValidName(name)})
}

// NewListOptionsForBackup returns a ListOptions based on the backup name.
// This is useful for interacting with client-go clients that needs a ListOptions.
func NewListOptionsForBackup(name string) metav1.ListOptions {
	return metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", velerov1api.BackupNameLabel, GetValidName(name)),
	}
}

// NewSelectorForRestore returns a Selector based on the restore name.
// This is useful for interacting with Listers that need a Selector.
func NewSelectorForRestore(name string) labels.Selector {
	return labels.SelectorFromSet(map[string]string{velerov1api.RestoreNameLabel: GetValidName(name)})
}
