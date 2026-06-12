//go:build linux
// +build linux

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

package kopia

import (
	"os"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

func flushVolume(dirPath string) error {
	dir, err := os.Open(dirPath)
	if err != nil {
		return errors.Wrapf(err, "error opening dir %v", dirPath)
	}

	raw, err := dir.SyscallConn()
	if err != nil {
		return errors.Wrapf(err, "error getting handle of dir %v", dirPath)
	}

	var syncErr error
	if err := raw.Control(func(fd uintptr) {
		if e := unix.Syncfs(int(fd)); e != nil {
			syncErr = e
		}
	}); err != nil {
		return errors.Wrapf(err, "error calling fs sync from %v", dirPath)
	}

	return errors.Wrapf(syncErr, "error syncing fs from %v", dirPath)
}
