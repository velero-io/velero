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

package dotenv

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Read parses dotenv-style files and returns merged key/value pairs.
func Read(filenames ...string) (map[string]string, error) {
	filenames = filenamesOrDefault(filenames)
	envMap := make(map[string]string)

	for _, filename := range filenames {
		fileMap, err := readFile(filename)
		if err != nil {
			return nil, err
		}

		for key, value := range fileMap {
			envMap[key] = value
		}
	}

	return envMap, nil
}

// Overload loads dotenv-style files into process env vars, overriding existing values.
func Overload(filenames ...string) error {
	filenames = filenamesOrDefault(filenames)

	for _, filename := range filenames {
		envMap, err := readFile(filename)
		if err != nil {
			return err
		}

		for key, value := range envMap {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func filenamesOrDefault(filenames []string) []string {
	if len(filenames) == 0 {
		return []string{".env"}
	}
	return filenames
}

func readFile(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	envMap := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = stripInlineComment(line)
		key, value, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		envMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envMap, nil
}

func stripInlineComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

func parseLine(line string) (string, string, error) {
	if strings.HasPrefix(line, "export ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	}

	sep := strings.Index(line, "=")
	colon := strings.Index(line, ":")
	if sep == -1 || (colon != -1 && colon < sep) {
		sep = colon
	}
	if sep == -1 {
		return "", "", fmt.Errorf("invalid dotenv line: %q", line)
	}

	key := strings.TrimSpace(line[:sep])
	rawValue := strings.TrimSpace(line[sep+1:])
	if key == "" {
		return "", "", fmt.Errorf("invalid dotenv line: %q", line)
	}

	value := parseValue(rawValue)
	return key, value, nil
}

func parseValue(value string) string {
	if len(value) >= 2 {
		if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			unquoted := strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
			unquoted = strings.ReplaceAll(unquoted, `\n`, "\n")
			unquoted = strings.ReplaceAll(unquoted, `\r`, "\r")
			unquoted = strings.ReplaceAll(unquoted, `\\`, `\`)
			unquoted = strings.ReplaceAll(unquoted, `\"`, `"`)
			return unquoted
		}
		if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
			return strings.TrimSuffix(strings.TrimPrefix(value, "'"), "'")
		}
	}

	return value
}
