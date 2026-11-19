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
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
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
		return nil
	}
}

// https://github.com/go-logfmt/logfmt/blob/e5396c6ee35145aead27da56e7921a7656f69624/encode.go#L235
func needsQuotedValueRune(r rune) bool {
	return r <= ' ' || r == '=' || r == '"' || r == 0x7f || r == utf8.RuneError
}

// Process logs (by adding color) before printing them
func processAndPrintLogs(r io.Reader, w io.Writer) error {
	reader := bufio.NewReader(r)
	var readErr error
	for readErr == nil {
		// Keep the original line so it can be printed unchanged if it cannot be colored.
		var raw string
		raw, readErr = reader.ReadString('\n')
		if raw == "" {
			break
		}

		// Parse the line
		d := logfmt.NewDecoder(strings.NewReader(raw))
		d.ScanRecord()

		// Scan fields and get color.
		var fields [][2][]byte
		var lineColor *color.Color
		for d.ScanKeyval() {
			fields = append(fields, [2][]byte{d.Key(), d.Value()})
			if string(d.Key()) == "level" {
				lineColor = getLevelColor(string(d.Value()))
			}
		}

		// Preserve the original line if it cannot be parsed or has no supported level color.
		if d.Err() != nil || lineColor == nil {
			if _, err := io.WriteString(w, raw); err != nil {
				return err
			}
			continue
		}

		// Re-encode with color. We do not use logfmt Encoder because it does not support color.
		for i, field := range fields {
			key := string(field[0])
			value := string(field[1])

			// Quote if needed
			if strings.IndexFunc(value, needsQuotedValueRune) != -1 {
				value = fmt.Sprintf("%q", value)
			}

			if key == "level" {
				colorCopy := *lineColor
				value = colorCopy.Add(color.Bold).Sprintf("%s", value)
			}
			key = lineColor.Sprintf("%s", field[0])

			if i != 0 {
				if _, err := fmt.Fprint(w, " "); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%s=%s", key, value); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if readErr != io.EOF {
		return fmt.Errorf("error processing logs: %w", readErr)
	}
	return nil
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

// PrintLogsWithColor streams logs to stdout, coloring logfmt records unless color is disabled.
// Close the writer before receiving the result to signal that no more logs will be written.
func PrintLogsWithColor() (io.WriteCloser, <-chan error) {
	result := make(chan error, 1)
	if color.NoColor {
		result <- nil
		close(result)
		return nopCloser{os.Stdout}, result
	}

	pr, pw := io.Pipe()
	stdout := os.Stdout
	go func() {
		defer close(result)
		err := processAndPrintLogs(pr, stdout)
		pr.CloseWithError(err)
		result <- err
	}()
	return pw, result
}
