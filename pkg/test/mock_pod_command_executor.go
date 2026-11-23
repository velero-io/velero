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
package test

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	v1 "github.com/velero-io/velero/pkg/apis/velero/v1"
)

type MockPodCommandExecutor struct {
	mock.Mock
	// hook execution order
	HookExecutionLog []HookExecutionEntry
}

type HookExecutionEntry struct {
	Namespace, Name, HookName string
	HookCommand               []string
}

func (h HookExecutionEntry) String() string {
	return fmt.Sprintf("%s.%s.%s.%s", h.Namespace, h.Name, h.HookName, strings.Join(h.HookCommand, ","))
}

func (e *MockPodCommandExecutor) ExecutePodCommand(log logrus.FieldLogger, item map[string]any, namespace, name, hookName string, hook *v1.ExecHook) error {
	e.HookExecutionLog = append(e.HookExecutionLog, HookExecutionEntry{
		Namespace:   namespace,
		Name:        name,
		HookName:    hookName,
		HookCommand: hook.Command,
	})
	args := e.Called(log, item, namespace, name, hookName, hook)
	return args.Error(0)
}
