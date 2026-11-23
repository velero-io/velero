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
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestDualModeLogger(t *testing.T) {
	logMsgExpect := "Expected message in log"
	logMsgUnexpect := "Unexpected message in log"

	logger, err := NewTempFileLogger(logrus.DebugLevel, FormatText, nil, logrus.Fields{})
	require.NoError(t, err)

	logger.Info(logMsgExpect)

	logger.DoneForPersist(velerotest.NewLogger())

	logger.Info(logMsgUnexpect)

	logFile, err := logger.GetPersistFile()
	require.NoError(t, err)

	logStr, err := readLogString(logFile)
	require.NoError(t, err)

	assert.Contains(t, logStr, logMsgExpect)
	assert.NotContains(t, logStr, logMsgUnexpect)

	logger.Dispose(velerotest.NewLogger())

	_, err = os.Stat(logFile.Name())

	assert.True(t, os.IsNotExist(err))
}

func readLogString(file *os.File) (string, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, 1024)
	_, err = gzr.Read(buffer)
	if err != io.EOF {
		return "", err
	}

	return string(buffer[:]), nil
}
