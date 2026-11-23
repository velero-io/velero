/*
Copyright the Velero contributors.

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

package kopia

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/velero-io/velero/pkg/test"
)

func TestEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		level    logrus.Level
		zapLevel zapcore.Level
		expected bool
	}{
		{
			name:     "check debug again debug",
			level:    logrus.DebugLevel,
			zapLevel: zapcore.DebugLevel,
			expected: true,
		},
		{
			name:     "check debug again info",
			level:    logrus.InfoLevel,
			zapLevel: zapcore.DebugLevel,
			expected: false,
		},
		{
			name:     "check info again debug",
			level:    logrus.DebugLevel,
			zapLevel: zapcore.InfoLevel,
			expected: true,
		},
		{
			name:     "check info again info",
			level:    logrus.InfoLevel,
			zapLevel: zapcore.InfoLevel,
			expected: true,
		},
		{
			name:     "check warn again warn",
			level:    logrus.WarnLevel,
			zapLevel: zapcore.WarnLevel,
			expected: true,
		},
		{
			name:     "check info again error",
			level:    logrus.ErrorLevel,
			zapLevel: zapcore.InfoLevel,
			expected: false,
		},
		{
			name:     "check error again error",
			level:    logrus.ErrorLevel,
			zapLevel: zapcore.ErrorLevel,
			expected: true,
		},
		{
			name:     "check dppanic again panic",
			level:    logrus.PanicLevel,
			zapLevel: zapcore.DPanicLevel,
			expected: true,
		},
		{
			name:     "check panic again error",
			level:    logrus.ErrorLevel,
			zapLevel: zapcore.PanicLevel,
			expected: true,
		},
		{
			name:     "check fatal again fatal",
			level:    logrus.FatalLevel,
			zapLevel: zapcore.FatalLevel,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log := kopiaLog{
				logger: test.NewLoggerWithLevel(tc.level),
			}
			m := log.Enabled(tc.zapLevel)

			require.Equal(t, tc.expected, m)
		})
	}
}

func TestLogrusFieldsForWrite(t *testing.T) {
	testCases := []struct {
		name      string
		module    string
		zapEntry  zapcore.Entry
		zapFields []zapcore.Field
		expected  logrus.Fields
	}{
		{
			name:   "debug with nil fields",
			module: "module-01",
			zapEntry: zapcore.Entry{
				Level: zapcore.DebugLevel,
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-01",
			},
		},
		{
			name:   "error with nil fields",
			module: "module-02",
			zapEntry: zapcore.Entry{
				Level: zapcore.ErrorLevel,
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-02",
				"sublevel":  "error",
			},
		},
		{
			name:   "info with nil string filed",
			module: "module-03",
			zapEntry: zapcore.Entry{
				Level: zapcore.InfoLevel,
			},
			zapFields: []zapcore.Field{
				{
					Key:    "key-01",
					Type:   zapcore.StringType,
					String: "value-01",
				},
			},
			expected: logrus.Fields{
				"logModule": "kopia/module-03",
				"key-01":    "value-01",
			},
		},
		{
			name:   "info with logger name",
			module: "module-04",
			zapEntry: zapcore.Entry{
				Level:      zapcore.InfoLevel,
				LoggerName: "logger-name-01",
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule":   "kopia/module-04",
				"logger name": "logger-name-01",
			},
		},
		{
			name:   "info with function name",
			module: "module-05",
			zapEntry: zapcore.Entry{
				Level: zapcore.InfoLevel,
				Caller: zapcore.EntryCaller{
					Function: "function-name-01",
				},
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-05",
				"function":  "function-name-01",
			},
		},
		{
			name:   "info with undefined path",
			module: "module-06",
			zapEntry: zapcore.Entry{
				Level: zapcore.InfoLevel,
				Caller: zapcore.EntryCaller{
					Defined: false,
				},
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-06",
			},
		},
		{
			name:   "info with defined path",
			module: "module-06",
			zapEntry: zapcore.Entry{
				Level: zapcore.InfoLevel,
				Caller: zapcore.EntryCaller{
					Defined: true,
					File:    "file-name-01",
					Line:    100,
				},
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-06",
				"path":      "file-name-01:100",
			},
		},
		{
			name:   "info with stack",
			module: "module-07",
			zapEntry: zapcore.Entry{
				Level: zapcore.InfoLevel,
				Stack: "fake-stack",
			},
			zapFields: nil,
			expected: logrus.Fields{
				"logModule": "kopia/module-07",
				"stack":     "fake-stack",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log := kopiaLog{
				module: tc.module,
				logger: test.NewLogger(),
			}
			m := log.logrusFieldsForWrite(tc.zapEntry, tc.zapFields)

			require.Equal(t, tc.expected, m)
		})
	}
}

func TestWrite(t *testing.T) {
	testCases := []struct {
		name        string
		ent         zapcore.Entry
		logMessage  string
		logLevel    string
		shouldPanic bool
	}{
		{
			name: "write debug",
			ent: zapcore.Entry{
				Level:   zapcore.DebugLevel,
				Message: "fake-message",
			},
			logMessage: "fake-message",
			logLevel:   "level=debug",
		},
		{
			name: "write info",
			ent: zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Message: "fake-message",
			},
			logMessage: "fake-message",
			logLevel:   "level=info",
		},
		{
			name: "write warn",
			ent: zapcore.Entry{
				Level:   zapcore.WarnLevel,
				Message: "fake-message",
			},
			logMessage: "fake-message",
			logLevel:   "level=warn",
		},
		{
			name: "write error",
			ent: zapcore.Entry{
				Level:   zapcore.ErrorLevel,
				Message: "fake-message",
			},
			logMessage: "fake-message",
			logLevel:   "level=warn",
		},
		{
			name: "write DPanic",
			ent: zapcore.Entry{
				Level:   zapcore.DPanicLevel,
				Message: "fake-message",
			},
			logMessage:  "fake-message",
			logLevel:    "level=panic",
			shouldPanic: true,
		},
		{
			name: "write panic",
			ent: zapcore.Entry{
				Level:   zapcore.PanicLevel,
				Message: "fake-message",
			},
			logMessage:  "fake-message",
			logLevel:    "level=panic",
			shouldPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logMessage := ""

			log := kopiaLog{
				logger: test.NewSingleLogger(&logMessage),
			}

			if tc.shouldPanic {
				defer func() {
					r := recover()
					assert.NotNil(t, r)

					if len(tc.logMessage) > 0 {
						assert.Contains(t, logMessage, tc.logMessage)
					}

					if len(tc.logLevel) > 0 {
						assert.Contains(t, logMessage, tc.logLevel)
					}
				}()
			}

			err := log.Write(tc.ent, nil)

			require.NoError(t, err)

			if len(tc.logMessage) > 0 {
				assert.Contains(t, logMessage, tc.logMessage)
			}

			if len(tc.logLevel) > 0 {
				assert.Contains(t, logMessage, tc.logLevel)
			}
		})
	}
}
