//go:build linux || darwin || freebsd || openbsd || netbsd || solaris

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
	"syscall"
)

// statOwner extracts the uid and gid from an os.FileInfo on Unix-like systems.
// It relies on the Sys() field being a *syscall.Stat_t, which is guaranteed on
// all platforms covered by the build constraint above.
func statOwner(info os.FileInfo) (uid, gid uint32) {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		return sys.Uid, sys.Gid
	}
	return 0, 0
}
