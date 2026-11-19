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
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Raw lines keep their exact bytes and do not prevent later records from being colored.
func TestProcessAndPrintLogsPreservesRawLines(t *testing.T) {
	noColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = noColor })

	raw := "this is hook output\r\n" +
		"  at main.main (file.go:12)\n" +
		"\t \n" +
		"level=info msg=\"unterminated\n" +
		"level 2 completed\n" +
		"level=  msg=empty\n" +
		"  level=INVALID  msg=\"unknown level\"\n" +
		"  msg=without-level\n" +
		"status=ok plain text\n"
	var out bytes.Buffer
	require.NoError(t, processAndPrintLogs(strings.NewReader(raw+"level=info\nlast raw line \t"), &out))

	green := color.New(color.FgGreen)
	boldGreen := color.New(color.FgGreen, color.Bold)
	want := raw + green.Sprint("level") + "=" + boldGreen.Sprint("info") + "\nlast raw line \t"
	assert.Equal(t, want, out.String())
}

// Test that a stdout failure reaches the downloader or the result channel, depending on when it occurs.
func TestPrintLogsWithColorWriteError(t *testing.T) {
	stdout, noColor := os.Stdout, color.NoColor
	t.Cleanup(func() {
		os.Stdout, color.NoColor = stdout, noColor
	})

	closedFile, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	require.NoError(t, closedFile.Close())
	os.Stdout = closedFile

	for _, tc := range []struct {
		name          string
		logs          string
		noColor       bool
		wantStreamErr error
		wantPrintErr  error
	}{
		{
			name:          "color failure unblocks an in-flight write",
			logs:          strings.Repeat(LOG_LINE+"\n", 1024),
			wantStreamErr: os.ErrClosed,
			wantPrintErr:  os.ErrClosed,
		},
		{
			name:         "color failure after the downloader finishes",
			logs:         LOG_LINE,
			wantPrintErr: os.ErrClosed,
		},
		{
			name:          "no color forwards stdout errors directly",
			logs:          LOG_LINE,
			noColor:       true,
			wantStreamErr: os.ErrClosed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			color.NoColor = tc.noColor
			w, result := PrintLogsWithColor()
			defer w.Close()

			var streamErr, printErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, streamErr = io.Copy(w, strings.NewReader(tc.logs))
				w.Close()
				printErr = <-result
			}()

			select {
			case <-done:
				require.ErrorIs(t, streamErr, tc.wantStreamErr)
				require.ErrorIs(t, printErr, tc.wantPrintErr)
			case <-time.After(5 * time.Second):
				t.Fatal("log streaming did not finish")
			}
		})
	}
}
