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
	"strconv"

	"github.com/cockroachdb/errors"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const (
	ParallelFilesUpload = "ParallelFilesUpload"
	WriteSparseFiles    = "WriteSparseFiles"
	RestoreConcurrency  = "ParallelFilesDownload"
	DeleteExtraFiles    = "DeleteExtraFiles"
)

func StoreBackupConfig(config *velerov1api.UploaderConfigForBackup) map[string]string {
	data := make(map[string]string)
	data[ParallelFilesUpload] = strconv.Itoa(config.ParallelFilesUpload)
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
