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
	"slices"

	"github.com/pkg/errors"
)

// Enum is a Cobra-compatible wrapper for defining
// a string flag that can be one of a specified set
// of values.
type Enum struct {
	allowedValues []string
	value         string
}

// NewEnum returns a new enum flag with the specified list
// of allowed values, and the specified default value if
// none is set.
func NewEnum(defaultValue string, allowedValues ...string) *Enum {
	return &Enum{
		allowedValues: allowedValues,
		value:         defaultValue,
	}
}

// String returns a string representation of the
// enum flag.
func (e *Enum) String() string {
	return e.value
}

// Set assigns the provided string to the enum
// receiver. It returns an error if the string
// is not an allowed value.
func (e *Enum) Set(s string) error {
	if slices.Contains(e.allowedValues, s) {
		e.value = s
		return nil
	}

	return errors.Errorf("invalid value: %q", s)
}

// Type returns a string representation of the
// Enum type.
func (e *Enum) Type() string {
	// we don't want the help text to display anything regarding
	// the type because the usage text for the flag should capture
	// the possible options.
	return ""
}

// AllowedValues returns a slice of the flag's valid
// values.
func (e *Enum) AllowedValues() []string {
	return e.allowedValues
}
