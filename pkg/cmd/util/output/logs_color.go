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
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/go-logfmt/logfmt"
)

func getLevelColor(level string) *color.Color {
	switch level {
	case "info":
		return color.New(color.FgGreen)
	case "warning":
		return color.New(color.FgYellow)
	case "error":
		return color.New(color.FgRed)
	case "debug":
		return color.New(color.FgBlue)
	default:
		return color.New()
	}
}

// https://github.com/go-logfmt/logfmt/blob/e5396c6ee35145aead27da56e7921a7656f69624/encode.go#L235
func needsQuotedValueRune(r rune) bool {
	return r <= ' ' || r == '=' || r == '"' || r == 0x7f || r == utf8.RuneError
}

// Process logs (by adding color) before printing them
func processAndPrintLogs(r io.Reader, w io.Writer) error {
	d := logfmt.NewDecoder(r)
	for d.ScanRecord() { // get record (line)
		// Scan fields and get color
		var fields [][2][]byte
		var lineColor *color.Color
		for d.ScanKeyval() {
			fields = append(fields, [2][]byte{d.Key(), d.Value()})
			if string(d.Key()) == "level" {
				lineColor = getLevelColor(string(d.Value()))
			}
		}

		// Re-encode with color. We do not use logfmt Encoder because it does not support color
		for i, field := range fields {
			key := string(field[0])
			value := string(field[1])

			// Quote if needed
			if strings.IndexFunc(value, needsQuotedValueRune) != -1 {
				value = fmt.Sprintf("%q", value)
			}

			// Add color
			if lineColor != nil { // handle case where no color (log level) was found
				if key == "level" {
					colorCopy := *lineColor
					value = colorCopy.Add(color.Bold).Sprintf("%s", value)
				}
				key = lineColor.Sprintf("%s", field[0])
			}
			if i != 0 {
				fmt.Fprint(w, " ")
			}
			fmt.Fprintf(w, "%s=%s", key, value)
		}
		fmt.Fprintln(w)
	}
	if err := d.Err(); err != nil {
		return fmt.Errorf("error processing logs: %v", err)
	}
	return nil
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

// Print logfmt-formatted logs to stdout with color based on log level
// if color.NoColor is set, logs will be directly piped to stdout without processing
// Returns the writer to write logs to, and a waitgroup to wait for processing to finish
// Writer must be closed once all logs have been written
// Note: this function is a wrapper around processAndPrintLogs to avoid always creating a goroutine
func PrintLogsWithColor() (io.WriteCloser, *sync.WaitGroup) {
	// If NoColor, do not parse logs and directly fall back to stdout
	var wg sync.WaitGroup
	if color.NoColor {
		return nopCloser{os.Stdout}, &wg
	} else {
		// Else, create a goroutine to process logs.
		wg.Add(1)
		pr, pw := io.Pipe()

		// Create coroutine to process logs
		go func(pr *io.PipeReader) {
			defer wg.Done()
			err := processAndPrintLogs(pr, os.Stdout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error processing logs: %v\n", err)
			}
		}(pr)
		return pw, &wg
	}
}
