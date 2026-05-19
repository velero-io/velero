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

package logging

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	logSourceField          = "logSource"
	logSourceSetMarkerField = "@logSourceSetBy"
	logrusPackage           = "github.com/sirupsen/logrus"
	veleroPackage           = "github.com/vmware-tanzu/velero/"
	veleroPackageLen        = len(veleroPackage)
)

// LogLocationHook is a logrus hook that attaches location information
// to log entries, i.e. the file and line number of the logrus log call.
// This hook is designed for use in both the Velero server and Velero plugin
// implementations. When triggered within a plugin, a marker field will
// be set on the log entry indicating that the location came from a plugin.
// The Velero server instance will not overwrite location information if
// it sees this marker.
type LogLocationHook struct {
	loggerName string
}

// WithLoggerName gives the hook a name to use when setting the marker field
// on a log entry indicating the location has been recorded by a plugin. This
// should only be used when setting up a hook for a logger used in a plugin.
func (h *LogLocationHook) WithLoggerName(name string) *LogLocationHook {
	h.loggerName = name
	return h
}

func (h *LogLocationHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *LogLocationHook) Fire(entry *logrus.Entry) error {
	pcs := make([]uintptr, 64)

	// skip 2 frames:
	//   runtime.Callers
	//   github.com/vmware-tanzu/velero/pkg/util/logging/(*LogLocationHook).Fire
	n := runtime.Callers(2, pcs)

	// re-slice pcs based on the number of entries written
	frames := runtime.CallersFrames(pcs[:n])

	// now traverse up the call stack looking for the first non-logrus
	// func, which will be the logrus invoker
	var (
		frame runtime.Frame
		more  = true
	)

	for more {
		frame, more = frames.Next()

		if strings.Contains(frame.File, logrusPackage) {
			continue
		}

		// set the marker field if we're within a plugin indicating that
		// the location comes from the plugin.
		if h.loggerName != "" {
			entry.Data[logSourceSetMarkerField] = h.loggerName
		}

		// record the log statement location if we're within a plugin OR if
		// we're in Velero server and not logging something that has the marker
		// set (which would indicate the log statement is coming from a plugin).
		if h.loggerName != "" || getLogSourceSetMarker(entry) == "" {
			file := removeVeleroPackagePrefix(frame.File)

			entry.Data[logSourceField] = fmt.Sprintf("%s:%d", file, frame.Line)
		}

		// if we're in the Velero server, remove the marker field since we don't
		// want to record it in the actual log.
		if h.loggerName == "" {
			delete(entry.Data, logSourceSetMarkerField)
		}

		break
	}

	return nil
}

func getLogSourceSetMarker(entry *logrus.Entry) string {
	nameVal, found := entry.Data[logSourceSetMarkerField]
	if !found {
		return ""
	}

	if name, ok := nameVal.(string); ok {
		return name
	}

	return fmt.Sprintf("%s", nameVal)
}

func removeVeleroPackagePrefix(file string) string {
	if _, after, ok := strings.Cut(file, veleroPackage); ok {
		// strip off .../github.com/vmware-tanzu/velero/ so we just have pkg/...
		return after
	}

	return file
}
