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

package logging

import (
	"fmt"
	"os"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeHook_Fire(t *testing.T) {
	tests := []struct {
		name       string
		entry      logrus.Entry
		expectHook bool
	}{
		{
			name: "normal message",
			entry: logrus.Entry{
				Level:   logrus.ErrorLevel,
				Message: "fake-message",
			},
			expectHook: false,
		},
		{
			name: "normal source",
			entry: logrus.Entry{
				Level:   logrus.ErrorLevel,
				Message: ListeningMessage,
				Data:    logrus.Fields{"fake-key": "fake-value"},
			},
			expectHook: false,
		},
		{
			name: "hook hit",
			entry: logrus.Entry{
				Level:   logrus.ErrorLevel,
				Message: ListeningMessage,
				Data:    logrus.Fields{LogSourceKey: "any-value"},
				Logger:  &logrus.Logger{},
			},
			expectHook: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hook := &MergeHook{}
			// method under test
			err := hook.Fire(&test.entry)

			require.NoError(t, err)

			if test.expectHook {
				assert.NotNil(t, test.entry.Logger.Out.(*hookWriter))
			}
		})
	}
}

type fakeWriter struct {
	p          []byte
	writeError error
	writtenLen int
}

func (fw *fakeWriter) Write(p []byte) (n int, err error) {
	if fw.writeError != nil || fw.writtenLen != -1 {
		return fw.writtenLen, fw.writeError
	}

	fw.p = append(fw.p, p...)

	return len(p), nil
}

func TestMergeHook_Write(t *testing.T) {
	sourceFile, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)

	logMessage := "fake-message-1\nfake-message-2"
	_, err = sourceFile.WriteString(logMessage)
	require.NoError(t, err)

	tests := []struct {
		name             string
		content          []byte
		source           string
		writeErr         error
		writtenLen       int
		expectError      string
		needRollBackHook bool
	}{
		{
			name:       "normal message",
			content:    []byte("fake-message"),
			writtenLen: -1,
		},
		{
			name:             "failed to open source file",
			content:          []byte(ListeningMessage),
			source:           "non-exist",
			needRollBackHook: true,
			expectError:      "open non-exist: no such file or directory",
		},
		{
			name:             "write error",
			content:          []byte(ListeningMessage),
			source:           sourceFile.Name(),
			writeErr:         errors.New("fake-error"),
			expectError:      "error to write log at pos 0: fake-error",
			needRollBackHook: true,
		},
		{
			name:             "write len mismatch",
			content:          []byte(ListeningMessage),
			source:           sourceFile.Name(),
			writtenLen:       100,
			expectError:      fmt.Sprintf("error to write log at pos 0, read %v but written 100", len(logMessage)),
			needRollBackHook: true,
		},
		{
			name:             "success",
			content:          []byte(ListeningMessage),
			source:           sourceFile.Name(),
			writtenLen:       -1,
			needRollBackHook: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := hookWriter{
				orgWriter: &fakeWriter{
					writeError: test.writeErr,
					writtenLen: test.writtenLen,
				},
				source: test.source,
				logger: &logrus.Logger{},
			}

			n, err := writer.Write(test.content)

			if test.expectError == "" {
				require.NoError(t, err)

				expectStr := string(test.content)
				if expectStr == ListeningMessage {
					expectStr = logMessage
				}

				assert.Len(t, expectStr, n)

				fakeWriter := writer.orgWriter.(*fakeWriter)
				writtenStr := string(fakeWriter.p)
				assert.Equal(t, writtenStr, expectStr)
			} else {
				require.EqualError(t, err, test.expectError)
			}

			if test.needRollBackHook {
				assert.Equal(t, writer.logger.Out, writer.orgWriter)
			}
		})
	}
}
