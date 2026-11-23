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

import (
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/velero-io/velero/pkg/cmd/util/flag"
)

var sortedLogLevels = sortLogLevels()

// LevelFlag is a command-line flag for setting the logrus
// log level.
type LevelFlag struct {
	*flag.Enum
	defaultValue logrus.Level
}

// LogLevelFlag constructs a new log level flag.
func LogLevelFlag(defaultValue logrus.Level) *LevelFlag {
	return &LevelFlag{
		Enum:         flag.NewEnum(defaultValue.String(), sortedLogLevels...),
		defaultValue: defaultValue,
	}
}

// Parse returns the flag's value as a logrus.Level.
func (f *LevelFlag) Parse() logrus.Level {
	if parsed, err := logrus.ParseLevel(f.String()); err == nil {
		return parsed
	}

	// This should theoretically never happen assuming the enum flag
	// is constructed correctly because the enum flag will not allow
	//  an invalid value to be set.
	logrus.Errorf("log-level flag has invalid value %s", strings.ToUpper(f.String()))
	return f.defaultValue
}

// sortLogLevels returns a string slice containing all of the valid logrus
// log levels (based on logrus.AllLevels), sorted in ascending order of severity.
func sortLogLevels() []string {
	var (
		sortedLogLevels  = make([]logrus.Level, len(logrus.AllLevels))
		logLevelsStrings []string
	)

	copy(sortedLogLevels, logrus.AllLevels)

	// logrus.Panic has the lowest value, so the compare function uses ">"
	sort.Slice(sortedLogLevels, func(i, j int) bool { return sortedLogLevels[i] > sortedLogLevels[j] })

	for _, level := range sortedLogLevels {
		logLevelsStrings = append(logLevelsStrings, level.String())
	}

	return logLevelsStrings
}
