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
package logging

import "github.com/velero-io/velero/pkg/cmd/util/flag"

// Format is a string representation of the desired output format for logs
type Format string

const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	defaultValue Format = FormatText
)

// FormatFlag is a command-line flag for setting the logrus
// log format.
type FormatFlag struct {
	*flag.Enum
	defaultValue Format
}

// NewFormatFlag constructs a new log level flag.
func NewFormatFlag() *FormatFlag {
	return &FormatFlag{
		Enum: flag.NewEnum(
			string(defaultValue),
			string(FormatText),
			string(FormatJSON),
		),
		defaultValue: defaultValue,
	}
}

// Parse returns the flag's value as a Format.
func (f *FormatFlag) Parse() Format {
	return Format(f.String())
}
