/*
Copyright 2018, 2019 the Velero contributors.

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
package framework

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/pkg/util/logging"
)

func TestNewLogger(t *testing.T) {
	l := newLogger()

	expectedFormatter := &logrus.JSONFormatter{
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyMsg: "@message",
		},
		DisableTimestamp: true,
	}
	assert.Equal(t, expectedFormatter, l.Formatter)

	expectedHooks := []logrus.Hook{
		(&logging.LogLocationHook{}).WithLoggerName("plugin"),
		&logging.ErrorLocationHook{},
		&logging.HcLogLevelHook{},
	}

	for _, level := range logrus.AllLevels {
		assert.Equal(t, expectedHooks, l.Hooks[level])
	}
}
