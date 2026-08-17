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

package util

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

const (
	ParallelFilesUpload  = "ParallelFilesUpload"
	ParallelBlocksUpload = "ParallelBlocksUpload"
	WriteSparseFiles     = "WriteSparseFiles"
	RestoreConcurrency   = "ParallelFilesDownload"
	DeleteExtraFiles     = "DeleteExtraFiles"

	// Exclude is the reserved transport key in PVB UploaderSettings and
	// DU DataMoverConfig. Value is a JSON-encoded []string.
	Exclude = "Exclude"
)

func StoreBackupConfig(config *velerov1api.UploaderConfigForBackup) map[string]string {
	data := make(map[string]string)
	data[ParallelFilesUpload] = strconv.Itoa(config.ParallelFilesUpload)
	data[ParallelBlocksUpload] = strconv.Itoa(config.ParallelBlocksUpload)
	return data
}

func StoreRestoreConfig(config *velerov1api.UploaderConfigForRestore) map[string]string {
	data := make(map[string]string)
	if config.WriteSparseFiles != nil {
		data[WriteSparseFiles] = strconv.FormatBool(*config.WriteSparseFiles)
	} else {
		data[WriteSparseFiles] = strconv.FormatBool(false)
	}

	if config.ParallelFilesDownload > 0 {
		data[RestoreConcurrency] = strconv.Itoa(config.ParallelFilesDownload)
	}

	if config.DeleteExtraFiles != nil {
		data[DeleteExtraFiles] = strconv.FormatBool(*config.DeleteExtraFiles)
	} else {
		data[DeleteExtraFiles] = strconv.FormatBool(false)
	}

	return data
}

func GetParallelFilesUpload(uploaderCfg map[string]string) (int, error) {
	parallelFilesUpload, ok := uploaderCfg[ParallelFilesUpload]
	if ok {
		parallelFilesUploadInt, err := strconv.Atoi(parallelFilesUpload)
		if err != nil {
			return 0, errors.Wrap(err, "failed to parse ParallelFilesUpload config")
		}
		return parallelFilesUploadInt, nil
	}
	return 0, nil
}

func GetParallelBlocksUpload(uploaderCfg map[string]string) (int, error) {
	parallelBlocksUpload, ok := uploaderCfg[ParallelBlocksUpload]
	if ok {
		parallelBlocksUploadInt, err := strconv.Atoi(parallelBlocksUpload)
		if err != nil {
			return 0, errors.Wrap(err, "failed to parse parallelBlocksUpload config")
		}
		return parallelBlocksUploadInt, nil
	}
	return 0, nil
}

func GetWriteSparseFiles(uploaderCfg map[string]string) (bool, error) {
	writeSparseFiles, ok := uploaderCfg[WriteSparseFiles]
	if ok {
		writeSparseFilesBool, err := strconv.ParseBool(writeSparseFiles)
		if err != nil {
			return false, errors.Wrap(err, "failed to parse WriteSparseFiles config")
		}
		return writeSparseFilesBool, nil
	}
	return false, nil
}

func GetRestoreConcurrency(uploaderCfg map[string]string) (int, error) {
	restoreConcurrency, ok := uploaderCfg[RestoreConcurrency]
	if ok {
		restoreConcurrencyInt, err := strconv.Atoi(restoreConcurrency)
		if err != nil {
			return 0, errors.Wrap(err, "failed to parse RestoreConcurrency config")
		}
		return restoreConcurrencyInt, nil
	}
	return 0, nil
}

func GetDeleteExtraFiles(uploaderCfg map[string]string) (bool, error) {
	deleteExtraFiles, ok := uploaderCfg[DeleteExtraFiles]
	if ok {
		deleteExtraFilesBool, err := strconv.ParseBool(deleteExtraFiles)
		if err != nil {
			return false, errors.Wrap(err, "failed to parse DeleteExtraFiles config")
		}
		return deleteExtraFilesBool, nil
	}
	return false, nil
}

func StoreExclude(patterns []string) (string, error) {
	if len(patterns) == 0 {
		return "", nil
	}
	b, err := json.Marshal(patterns)
	if err != nil {
		return "", fmt.Errorf("failed to JSON-encode exclude patterns: %w", err)
	}
	return string(b), nil
}

func GetExclude(uploaderCfg map[string]string) ([]string, error) {
	raw, ok := uploaderCfg[Exclude]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var patterns []string
	if err := json.Unmarshal([]byte(raw), &patterns); err != nil {
		return nil, fmt.Errorf("invalid %q config (expected JSON-encoded string array): %w", Exclude, err)
	}
	return patterns, nil
}

// MergeExclude JSON-encodes patterns into cfg under the Exclude key.
// Empty lists leave cfg unchanged (the key is not written). A nil cfg is
// allocated only when a non-empty payload must be stored.
func MergeExclude(cfg map[string]string, patterns []string) (map[string]string, error) {
	serialized, err := StoreExclude(patterns)
	if err != nil {
		return nil, err
	}
	if serialized == "" {
		return cfg, nil
	}
	if cfg == nil {
		cfg = make(map[string]string)
	}
	cfg[Exclude] = serialized
	return cfg, nil
}
