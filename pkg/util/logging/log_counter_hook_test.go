package logging

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/util/results"
)

func TestLogHook_Fire(t *testing.T) {
	hook := NewLogHook()

	entry := &logrus.Entry{
		Level: logrus.ErrorLevel,
		Data: logrus.Fields{
			"namespace": "test-namespace",
			"error":     errors.New("test-error"),
			"resource":  "test-resource",
			"name":      "test-name",
		},
		Message: "test-message",
	}

	err := hook.Fire(entry)
	require.NoError(t, err)

	// Verify the counts
	assert.Equal(t, 1, hook.counts[logrus.ErrorLevel])

	// Verify the entries
	expectedResult := &results.Result{}
	expectedResult.Add("test-namespace", fmt.Errorf(" resource: /test-resource name: /test-name message: /test-message error: /%v", entry.Data["error"]))
	assert.Equal(t, expectedResult, hook.entries[logrus.ErrorLevel])

	entry1 := &logrus.Entry{
		Level: logrus.ErrorLevel,
		Data: logrus.Fields{
			"error.message": errors.New("test-error"),
			"resource":      "test-resource",
			"name":          "test-name",
		},
		Message: "test-message",
	}

	err = hook.Fire(entry1)
	require.NoError(t, err)

	// Verify the counts
	assert.Equal(t, 2, hook.counts[logrus.ErrorLevel])

	// Verify the entries
	expectedResult = &results.Result{}
	expectedResult.Add("test-namespace", fmt.Errorf(" resource: /test-resource name: /test-name message: /test-message error: /%v", entry.Data["error"]))
	expectedResult.AddVeleroError(fmt.Errorf(" resource: /test-resource name: /test-name message: /test-message error: /%v", entry1.Data["error.message"]))
	assert.Equal(t, expectedResult, hook.entries[logrus.ErrorLevel])
}

func TestLogHook_Levels(t *testing.T) {
	hook := NewLogHook()

	levels := hook.Levels()

	expectedLevels := []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}

	assert.Equal(t, expectedLevels, levels)
}

func TestLogHook_GetCount(t *testing.T) {
	hook := NewLogHook()

	// Set up test data
	hook.counts[logrus.ErrorLevel] = 5
	hook.counts[logrus.WarnLevel] = 10

	// Test GetCount for ErrorLevel
	count := hook.GetCount(logrus.ErrorLevel)
	assert.Equal(t, 5, count)

	// Test GetCount for WarnLevel
	count = hook.GetCount(logrus.WarnLevel)
	assert.Equal(t, 10, count)

	// Test GetCount for other levels
	count = hook.GetCount(logrus.InfoLevel)
	assert.Equal(t, 0, count)

	count = hook.GetCount(logrus.DebugLevel)
	assert.Equal(t, 0, count)
}

func TestLogHook_GetEntries(t *testing.T) {
	hook := NewLogHook()

	// Set up test data
	entry := &logrus.Entry{
		Level: logrus.ErrorLevel,
		Data: logrus.Fields{
			"namespace": "test-namespace",
			"error":     errors.New("test-error"),
			"resource":  "test-resource",
			"name":      "test-name",
		},
		Message: "test-message",
	}
	expectedResult := &results.Result{}
	expectedResult.Add("test-namespace", fmt.Errorf(" resource: /test-resource name: /test-name message: /test-message error: /%v", entry.Data["error"]))
	hook.entries[logrus.ErrorLevel] = expectedResult

	// Test GetEntries for ErrorLevel
	result := hook.GetEntries(logrus.ErrorLevel)
	assert.Equal(t, *expectedResult, result)

	// Test GetEntries for WarnLevel
	result = hook.GetEntries(logrus.WarnLevel)
	assert.Equal(t, results.Result{}, result)

	// Test GetEntries for other levels
	result = hook.GetEntries(logrus.InfoLevel)
	assert.Equal(t, results.Result{}, result)

	result = hook.GetEntries(logrus.DebugLevel)
	assert.Equal(t, results.Result{}, result)
}
