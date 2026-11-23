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

package logging

import (
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/velero-io/velero/pkg/util/results"
)

// LogHook is a logrus hook that counts the number of log
// statements that have been written at each logrus level. It also
// maintains log entries at each logrus level in result structure.
type LogHook struct {
	mu      sync.RWMutex
	counts  map[logrus.Level]int
	entries map[logrus.Level]*results.Result
}

// NewLogHook returns a pointer to an initialized LogHook.
func NewLogHook() *LogHook {
	return &LogHook{
		counts:  make(map[logrus.Level]int),
		entries: make(map[logrus.Level]*results.Result),
	}
}

// Levels returns the logrus levels that the hook should be fired for.
func (h *LogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire executes the hook's logic.
func (h *LogHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.counts[entry.Level]++
	if h.entries[entry.Level] == nil {
		h.entries[entry.Level] = &results.Result{}
	}

	namespace, isNamespacePresent := entry.Data["namespace"]
	errorField, isErrorFieldPresent := entry.Data["error"]
	// When JSON logging format is enabled, error message is placed at "error.message" instead of "error"
	errorMsgField, isErrorMsgFieldPresent := entry.Data["error.message"]
	resourceField, isResourceFieldPresent := entry.Data["resource"]
	nameField, isNameFieldPresent := entry.Data["name"]
	msgField, isMsgFieldPresent := entry.Message, true

	entryMessage := ""
	if isResourceFieldPresent {
		entryMessage = fmt.Sprintf("%s resource: /%s", entryMessage, resourceField.(string))
	}
	if isNameFieldPresent {
		entryMessage = fmt.Sprintf("%s name: /%s", entryMessage, nameField.(string))
	}
	if isMsgFieldPresent {
		entryMessage = fmt.Sprintf("%s message: /%v", entryMessage, msgField)
	}
	if isErrorFieldPresent {
		entryMessage = fmt.Sprintf("%s error: /%v", entryMessage, errorField)
	}
	if isErrorMsgFieldPresent {
		entryMessage = fmt.Sprintf("%s error: /%v", entryMessage, errorMsgField)
	}

	if isNamespacePresent {
		h.entries[entry.Level].Add(namespace.(string), errors.New(entryMessage))
	} else {
		h.entries[entry.Level].AddVeleroError(errors.New(entryMessage))
	}
	return nil
}

// GetCount returns the number of log statements that have been
// written at the specific level provided.
func (h *LogHook) GetCount(level logrus.Level) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.counts[level]
}

// GetEntries returns the log statements that have been
// written at the specific level provided.
func (h *LogHook) GetEntries(level logrus.Level) results.Result {
	h.mu.RLock()
	defer h.mu.RUnlock()
	response, isPresent := h.entries[level]
	if isPresent {
		return *response
	}
	return results.Result{}
}
