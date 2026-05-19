/*
Copyright 2018 the Velero contributors.

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

package stringslice

import "slices"

// Has returns true if the `items` slice contains the
// value `val`, or false otherwise.
func Has(items []string, val string) bool {
	return slices.Contains(items, val)
}

// Except returns a new string slice that contains all of the entries
// from `items` except `val`.
func Except(items []string, val string) []string {
	// Default the capacity the len(items) instead of len(items)-1 in case items does not contain val.
	newItems := make([]string, 0, len(items))

	for _, itm := range items {
		if itm != val {
			newItems = append(newItems, itm)
		}
	}

	return newItems
}
