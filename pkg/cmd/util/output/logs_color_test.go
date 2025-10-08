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
package output

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var LOG_LINE = "level=info msg=\"This is a test log\" key1=value1 key2=\"value with spaces\""
var LOG_LINE_2 = "level=INVALID msg=\"This is a second test log\" key1=value1 key2=\"value 2 with spaces\""
var LOG_LINE_3 = "level=error msg=\"This is a thirdtest log\" key1=value1 key2=\"value 3 with spaces\""

// Note that all comparisons in this file work because color.NoColor is set to false by default, and thus no colors are added, even
// through the color adding code is run.

func TestColoredLogHasLog(t *testing.T) {
	inputBuf := &bytes.Buffer{}
	inputBuf.WriteString(LOG_LINE)

	outputBuf := &bytes.Buffer{}
	err := processAndPrintLogs(inputBuf, outputBuf)
	if err != nil {
		t.Fatalf("processAndPrintLogs returned error: %v", err)
	}

	assert.Contains(t, outputBuf.String(), "This is a test log")
}

// Test log line is unchanged since log is decomposed and re-composed
func TestColoredLogIsSameAsUncoloredLog(t *testing.T) {
	inputBuf := &bytes.Buffer{}
	inputBuf.WriteString(LOG_LINE)

	outputBuf := &bytes.Buffer{}
	err := processAndPrintLogs(inputBuf, outputBuf)
	if err != nil {
		t.Fatalf("processAndPrintLogs returned error: %v", err)
	}

	assert.Equal(t, LOG_LINE+"\n", outputBuf.String())
}

// Test all log lines are sent correctly (and unchanged)
func TestMultipleColoredLogs(t *testing.T) {
	inputBuf := &bytes.Buffer{}
	inputBuf.WriteString(LOG_LINE)
	inputBuf.WriteString("\n")
	inputBuf.WriteString(LOG_LINE_2)
	inputBuf.WriteString("\n")
	inputBuf.WriteString(LOG_LINE_3)

	outputBuf := &bytes.Buffer{}
	err := processAndPrintLogs(inputBuf, outputBuf)
	if err != nil {
		t.Fatalf("processAndPrintLogs returned error: %v", err)
	}

	assert.Equal(t, fmt.Sprintf("%v\n%v\n%v\n", LOG_LINE, LOG_LINE_2, LOG_LINE_3), outputBuf.String())
}
