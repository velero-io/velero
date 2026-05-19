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
	"slices"
)

func Contains(slice []string, key string) bool {
	return slices.Contains(slice, key)
}

// GenerateSha256FromRestoreUIDAndVsName Use the restore UID and the VS Name to generate
// the new VSC and VS name. By this way, VS and VSC RIA action can get the same VSC name.
func GenerateSha256FromRestoreUIDAndVsName(restoreUID string, vsName string) string {
	sha256Bytes := sha256.Sum256([]byte(restoreUID + "/" + vsName))
	return hex.EncodeToString(sha256Bytes[:])
}
