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

	"github.com/vmware-tanzu/velero/pkg/util"
)

// StringArray is a Cobra-compatible named type for defining a
// string slice flag.
type StringArray []string

// NewStringArray returns a StringArray for a provided
// slice of values.
func NewStringArray(initial ...string) StringArray {
	return StringArray(initial)
}

// String returns a comma-separated list of the items
// in the string array.
func (sa *StringArray) String() string {
	return strings.Join(*sa, ",")
}

// Set comma-splits the provided string and assigns
// the results to the receiver. It returns an error if
// the string is not parseable.
func (sa *StringArray) Set(s string) error {
	*sa = StringArray(util.SplitAndTrimCSV(s))
	return nil
}

// Type returns a string representation of the
// StringArray type.
func (sa *StringArray) Type() string {
	return "stringArray"
}
