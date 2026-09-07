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

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func Contains(slice []string, key string) bool {
	for _, i := range slice {
		if i == key {
			return true
		}
	}
	return false
}

// SplitAndTrimCSV splits a comma-separated string, trims whitespace from each
// entry, and drops empty entries. This makes values like
// "EnableCSI, EnableAPIGroupVersions" parse as the intended names.
func SplitAndTrimCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

// GenerateSha256FromRestoreUIDAndVsName Use the restore UID and the VS Name to generate
// the new VSC and VS name. By this way, VS and VSC RIA action can get the same VSC name.
func GenerateSha256FromRestoreUIDAndVsName(restoreUID string, vsName string) string {
	sha256Bytes := sha256.Sum256([]byte(restoreUID + "/" + vsName))
	return hex.EncodeToString(sha256Bytes[:])
}
