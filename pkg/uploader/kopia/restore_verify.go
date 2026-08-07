//go:build !windows
// +build !windows

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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/kopia/kopia/fs"
)

const (
	// maxAttrVerifyEntries caps how many restored entries are verified. Attribute
	// loss is caused by the nature of the target volume's mount (e.g. root-squashed
	// NFS, CIFS/FUSE mounts with a fixed identity), which affects all entries in the
	// volume the same way, so verifying a small sample is enough to detect it without
	// impacting the restore throughput in the large scale cases.
	maxAttrVerifyEntries = 50

	// maxAttrMismatchSamples caps how many mismatched entries are listed in the warning log.
	maxAttrMismatchSamples = 5
)

type attrMismatch struct {
	localPath     string
	uid           uint32
	gid           uint32
	mode          os.FileMode
	ownerMismatch bool
}

type attrVerifyResult struct {
	checked       int
	ownerMismatch int
	modeMismatch  int
	samples       []string
	first         *attrMismatch
}

// verifyRestoredAttrs samples up to maxAttrVerifyEntries entries restored under
// targetPath and compares the owner (uid:gid) and permission bits on disk with the
// metadata recorded in the snapshot. The restore runs with IgnorePermissionErrors,
// so a chown/chmod rejected by the target volume is silently swallowed; and some
// mounts even report success for chown/chmod without applying anything. Both end
// up as a completed restore with wrong attributes. This check makes such restores
// visible through a warning log; it never fails the restore.
func verifyRestoredAttrs(ctx context.Context, rootEntry fs.Entry, targetPath string, log logrus.FieldLogger) {
	rootDir, ok := rootEntry.(fs.Directory)
	if !ok {
		return
	}

	result := attrVerifyResult{}

	type pendingDir struct {
		dir     fs.Directory
		relPath string
	}

	pending := []pendingDir{{dir: rootDir}}

	for len(pending) > 0 && result.checked < maxAttrVerifyEntries {
		cur := pending[0]
		pending = pending[1:]

		iter, err := cur.dir.Iterate(ctx)
		if err != nil {
			log.WithError(err).Debugf("Failed to iterate snapshot directory %q to verify restored attributes", cur.relPath)
			continue
		}

		entry, err := iter.Next(ctx)
		for entry != nil && result.checked < maxAttrVerifyEntries {
			relPath := filepath.Join(cur.relPath, entry.Name())

			if subDir, ok := entry.(fs.Directory); ok {
				pending = append(pending, pendingDir{dir: subDir, relPath: relPath})
			}

			verifyEntryAttrs(entry, relPath, targetPath, &result)

			entry, err = iter.Next(ctx)
		}

		iter.Close()

		if err != nil {
			log.WithError(err).Debugf("Failed to iterate snapshot directory %q to verify restored attributes", cur.relPath)
		}
	}

	if result.ownerMismatch == 0 && result.modeMismatch == 0 {
		log.Debugf("Verified owner/permissions of %d entries restored to %s", result.checked, targetPath)
		return
	}

	log.Warnf("Restored data in %s doesn't match the owner/permissions recorded in the snapshot (%d of %d checked entries with unexpected owner, %d with unexpected permissions; %s), samples: [%s]. The volume's mount likely cannot apply these attributes, e.g. root-squashed NFS or CIFS/FUSE mounts with a fixed identity",
		targetPath, result.ownerMismatch, result.checked, result.modeMismatch, classifyAttrMismatch(result.first), strings.Join(result.samples, "; "))
}

// verifyEntryAttrs compares the on-disk owner and permission bits of the entry
// restored to targetPath/relPath with the ones recorded in the snapshot entry and
// accumulates mismatches into result.
func verifyEntryAttrs(entry fs.Entry, relPath, targetPath string, result *attrVerifyResult) {
	// Symlinks and special files need OS specific attribute handling in kopia;
	// regular files and directories are enough to detect a volume that cannot
	// apply the attributes recorded in the snapshot.
	if !entry.Mode().IsRegular() && !entry.Mode().IsDir() {
		return
	}

	localPath := filepath.Join(targetPath, relPath)

	st, err := os.Lstat(localPath)
	if err != nil {
		return
	}

	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	result.checked++

	owner := entry.Owner()
	expectedMode := entry.Mode() & fs.ModBits
	actualMode := st.Mode() & fs.ModBits

	ownerMatch := sys.Uid == owner.UserID && sys.Gid == owner.GroupID
	modeMatch := actualMode == expectedMode

	if ownerMatch && modeMatch {
		return
	}

	if !ownerMatch {
		result.ownerMismatch++
	}

	if !modeMatch {
		result.modeMismatch++
	}

	if result.first == nil {
		result.first = &attrMismatch{
			localPath:     localPath,
			uid:           owner.UserID,
			gid:           owner.GroupID,
			mode:          expectedMode,
			ownerMismatch: !ownerMatch,
		}
	}

	if len(result.samples) < maxAttrMismatchSamples {
		result.samples = append(result.samples, fmt.Sprintf("%s: expected %d:%d %04o, observed %d:%d %04o",
			relPath, owner.UserID, owner.GroupID, modeOctal(expectedMode), sys.Uid, sys.Gid, modeOctal(actualMode)))
	}
}

// classifyAttrMismatch re-applies the expected attribute on one mismatched entry to
// differentiate the known failure modes: the volume rejecting the change with an
// error that was swallowed by IgnorePermissionErrors during the restore, or the
// volume acknowledging the change without applying it.
func classifyAttrMismatch(m *attrMismatch) string {
	if m.ownerMismatch {
		maxInt := uint64(^uint(0) >> 1)
		if uint64(m.uid) > maxInt || uint64(m.gid) > maxInt {
			return fmt.Sprintf("chown cannot be retried on this platform (uid/gid out of int range): %d:%d", m.uid, m.gid)
		}
		if err := os.Chown(m.localPath, int(m.uid), int(m.gid)); err != nil {
			return fmt.Sprintf("chown is rejected by the volume: %v", err)
		}

		if st, err := os.Lstat(m.localPath); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (sys.Uid != m.uid || sys.Gid != m.gid) {
				return "chown reports success but is silently ignored by the volume"
			}
		}

		return "chown succeeded when retried"
	}

	if err := os.Chmod(m.localPath, m.mode); err != nil {
		return fmt.Sprintf("chmod is rejected by the volume: %v", err)
	}

	if st, err := os.Lstat(m.localPath); err == nil && st.Mode()&fs.ModBits != m.mode {
		return "chmod reports success but is silently ignored by the volume"
	}

	return "chmod succeeded when retried"
}

// modeOctal converts an os.FileMode to the familiar octal representation,
// including the setuid/setgid/sticky bits.
func modeOctal(mode os.FileMode) uint32 {
	bits := uint32(mode.Perm())

	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}

	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}

	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}

	return bits
}
