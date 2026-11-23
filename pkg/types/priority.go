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

package types

import (
	"fmt"
	"strings"
)

const (
	prioritySeparator = "-"
)

// Priorities defines the desired order of resource operations:
// Resources in the HighPriorities list will be handled first
// Resources in the LowPriorities list will be handled last
// Other resources will be handled alphabetically after the high prioritized resources and before the low prioritized resources
type Priorities struct {
	HighPriorities []string
	LowPriorities  []string
}

// String returns a string representation of Priority.
func (p *Priorities) String() string {
	priorities := make([]string, 0, len(p.HighPriorities)+1+len(p.LowPriorities))
	priorities = append(priorities, p.HighPriorities...)
	if len(p.LowPriorities) > 0 {
		priorities = append(priorities, prioritySeparator)
		priorities = append(priorities, p.LowPriorities...)
	}
	return strings.Join(priorities, ",")
}

// Set parses the provided string to the priority object
func (p *Priorities) Set(s string) error {
	if len(s) == 0 {
		return nil
	}
	strs := strings.Split(s, ",")
	separatorIndex := -1
	for i, str := range strs {
		if str == prioritySeparator {
			if separatorIndex > -1 {
				return fmt.Errorf("multiple priority separator %q found", prioritySeparator)
			}
			separatorIndex = i
		}
	}
	// has no separator
	if separatorIndex == -1 {
		p.HighPriorities = strs
		return nil
	}
	// start with separator
	if separatorIndex == 0 {
		// contain only separator
		if len(strs) == 1 {
			return nil
		}
		p.LowPriorities = strs[1:]
		return nil
	}
	// end with separator
	if separatorIndex == len(strs)-1 {
		p.HighPriorities = strs[: len(strs)-1 : len(strs)-1]
		return nil
	}

	// separator in the middle. Cap HighPriorities at its length so that
	// appending to it cannot overwrite the separator or LowPriorities, which
	// share the same backing array.
	p.HighPriorities = strs[:separatorIndex:separatorIndex]
	p.LowPriorities = strs[separatorIndex+1:]

	return nil
}

// Type specifies the flag type
func (p *Priorities) Type() string {
	return "stringArray"
}
