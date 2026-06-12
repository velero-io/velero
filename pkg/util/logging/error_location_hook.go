/*
Copyright 2017, 2019 the Velero contributors.

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
	"strconv"
	"strings"

	"github.com/cockroachdb/errors/errbase"
	"github.com/sirupsen/logrus"
)

const (
	errorFileField     = "error.file"
	errorFunctionField = "error.function"
)

// ErrorLocationHook is a logrus hook that attaches error location information
// to log entries if an error is being logged and it has stack-trace information
// (i.e. if it carries a stack trace from wrapped errors), or if it
// implements the errorLocationer interface, like errors returned from plugins
// typically do).
type ErrorLocationHook struct{}

func (h *ErrorLocationHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *ErrorLocationHook) Fire(entry *logrus.Entry) error {
	errObj, ok := entry.Data[logrus.ErrorKey]
	if !ok {
		return nil
	}

	if _, ok := entry.Data[errorFileField]; ok {
		// If there is already an error file field, preserve it instead of overwriting it. This field will already exist if
		// the log message occurred in the server half of a plugin.
		return nil
	}
	if _, ok := entry.Data[errorFunctionField]; ok {
		// If there is already an error function field, preserve it instead of overwriting it. This field will already exist if
		// the log message occurred in the server half of a plugin.
		return nil
	}

	err, ok := errObj.(error)
	if !ok {
		// if the value isn't an error type, skip trying to get location info,
		// and just let it be logged as whatever it was
		return nil
	}

	if errorLocationer, ok := err.(errorLocationer); ok {
		entry.Data[errorFileField] = fmt.Sprintf("%s:%d", errorLocationer.File(), errorLocationer.Line())
		entry.Data[errorFunctionField] = errorLocationer.Function()
		return nil
	}

	if stackErr := getInnermostTrace(err); stackErr != nil {
		location := GetFrameLocationInfo(stackErr.StackTrace()[0])

		entry.Data[errorFileField] = fmt.Sprintf("%s:%d", location.File, location.Line)
		entry.Data[errorFunctionField] = location.Function
	}

	return nil
}

// LocationInfo specifies the location of a line
// of code.
type LocationInfo struct {
	File     string
	Function string
	Line     int
}

// GetFrameLocationInfo returns the location of a frame.
func GetFrameLocationInfo(frame errbase.StackFrame) LocationInfo {
	// see https://pkg.go.dev/github.com/cockroachdb/errors#Frame.Format for
	// details on formatting verbs
	functionNameAndFileAndLine := fmt.Sprintf("%+v", frame)

	newLineIndex := strings.Index(functionNameAndFileAndLine, "\n")
	functionName := functionNameAndFileAndLine[0:newLineIndex]

	tabIndex := strings.LastIndex(functionNameAndFileAndLine, "\t")
	fileAndLine := strings.Split(functionNameAndFileAndLine[tabIndex+1:], ":")

	line, err := strconv.Atoi(fileAndLine[1])
	if err != nil {
		line = -1
	}

	return LocationInfo{
		File:     fileAndLine[0],
		Function: functionName,
		Line:     line,
	}
}

type errorLocationer interface {
	File() string
	Line() int32
	Function() string
}

type stackTracer interface {
	error
	StackTrace() errbase.StackTrace
}

type causer interface {
	Cause() error
}

// getInnermostTrace returns the innermost error that
// has a stack trace attached
func getInnermostTrace(err error) stackTracer {
	var tracer stackTracer

	for {
		t, isTracer := err.(stackTracer)
		if isTracer {
			tracer = t
		}

		c, isCauser := err.(causer)
		if isCauser {
			err = c.Cause()
		} else {
			return tracer
		}
	}
}
