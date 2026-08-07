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
	"runtime"
	"sync/atomic"

	"github.com/kopia/kopia/fs"
	"github.com/kopia/kopia/snapshot"
	"github.com/kopia/kopia/snapshot/restore"
)

// maxAttrMismatchSamples caps the number of representative mismatch paths kept
// in memory for log output, preventing unbounded growth on pathological volumes.
const maxAttrMismatchSamples = 10

// AttrMismatch describes one file whose ownership or mode did not match the
// expected value after kopia called chown/chmod. This is evidence of a silent
// attribute loss caused either by:
//   - NFS root_squash / NFSv4 idmap: server returns EPERM which is swallowed
//     by IgnorePermissionErrors (hardcoded true in Restore).
//   - Azure Files SMB / blobfuse / gcsfuse: the syscall returns exit-0 but
//     the mount silently ignores the request.
type AttrMismatch struct {
	// Path is the absolute path of the restored entry.
	Path string
	// ExpectedUID / ExpectedGID are the uid/gid kopia tried to set.
	ExpectedUID uint32
	ExpectedGID uint32
	// ActualUID / ActualGID are the uid/gid reported by lstat after chown.
	ActualUID uint32
	ActualGID uint32
	// ExpectedMode / ActualMode are the permission bits kopia tried to set and
	// the bits lstat reports; zero when only ownership was checked.
	ExpectedMode os.FileMode
	ActualMode   os.FileMode
}

// String returns a concise one-liner suitable for log messages.
func (m AttrMismatch) String() string {
	return fmt.Sprintf(
		"%s: expected uid:gid=%d:%d mode=%04o, got uid:gid=%d:%d mode=%04o",
		m.Path,
		m.ExpectedUID, m.ExpectedGID, m.ExpectedMode,
		m.ActualUID, m.ActualGID, m.ActualMode,
	)
}

// ownershipVerifier accumulates attribute mismatches detected during a restore
// walk. It is goroutine-safe: restore.Entry processes files concurrently.
type ownershipVerifier struct {
	// mismatchCount is atomically incremented for every detected mismatch.
	mismatchCount atomic.Int64

	// mu serialises access to samples via a 1-slot buffered channel.
	mu      chan struct{}
	samples []AttrMismatch
}

// newOwnershipVerifier returns an initialised, ready-to-use ownershipVerifier.
func newOwnershipVerifier() *ownershipVerifier {
	v := &ownershipVerifier{
		mu:      make(chan struct{}, 1),
		samples: make([]AttrMismatch, 0, maxAttrMismatchSamples),
	}
	v.mu <- struct{}{} // start unlocked
	return v
}

// MismatchCount returns the total number of entries with detected mismatches.
func (v *ownershipVerifier) MismatchCount() int64 {
	return v.mismatchCount.Load()
}

// Samples returns a copy of the capped sample slice for log output.
func (v *ownershipVerifier) Samples() []AttrMismatch {
	<-v.mu
	defer func() { v.mu <- struct{}{} }()
	out := make([]AttrMismatch, len(v.samples))
	copy(out, v.samples)
	return out
}

// checkOwnership performs an lstat on absPath and records a mismatch if the
// actual uid/gid differs from (expectedUID, expectedGID).
// This is a no-op on Windows where chown is unsupported.
func (v *ownershipVerifier) checkOwnership(absPath string, expectedUID, expectedGID uint32) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return // best-effort; missing file is not an ownership mismatch
	}
	uid, gid := statOwner(info)
	if uid == expectedUID && gid == expectedGID {
		return
	}
	v.record(AttrMismatch{
		Path:        absPath,
		ExpectedUID: expectedUID,
		ExpectedGID: expectedGID,
		ActualUID:   uid,
		ActualGID:   gid,
	})
}

// checkMode performs an lstat on absPath and records a mismatch if the actual
// permission bits differ from expectedMode.
// This is a no-op on Windows where chmod semantics are fundamentally different.
func (v *ownershipVerifier) checkMode(absPath string, expectedMode os.FileMode) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return
	}
	actual := info.Mode().Perm()
	if actual == expectedMode {
		return
	}
	v.record(AttrMismatch{
		Path:         absPath,
		ExpectedMode: expectedMode,
		ActualMode:   actual,
	})
}

// record increments the total counter and appends to the sample list up to
// maxAttrMismatchSamples. Beyond that only the counter grows.
func (v *ownershipVerifier) record(m AttrMismatch) {
	v.mismatchCount.Add(1)
	<-v.mu
	defer func() { v.mu <- struct{}{} }()
	if len(v.samples) < maxAttrMismatchSamples {
		v.samples = append(v.samples, m)
	}
}

// --------------------------------------------------------------------------
// verifyingRestoreOutput
// --------------------------------------------------------------------------

// verifyingRestoreOutput wraps fileSystemRestoreOutput and, after every
// WriteFile / FinishDirectory / CreateSymlink call, reads back the filesystem
// attributes with lstat and compares them to the values kopia tried to set.
//
// This catches both known silent-failure modes (issue #10043):
//  1. NFS root_squash / NFSv4 idmap: chown returns EPERM, swallowed by
//     IgnorePermissionErrors — we still detect the attribute mismatch.
//  2. Azure Files SMB / blobfuse / gcsfuse: chown/chmod returns exit-0 but is
//     a no-op — only post-call lstat can reveal the discrepancy.
//
// verifyingRestoreOutput fully implements the RestoreOutput interface by
// delegating every method to its inner fileSystemRestoreOutput.
type verifyingRestoreOutput struct {
	inner    *fileSystemRestoreOutput
	verifier *ownershipVerifier
}

// Compile-time assertion: verifyingRestoreOutput must satisfy RestoreOutput.
var _ RestoreOutput = (*verifyingRestoreOutput)(nil)

// newVerifyingRestoreOutput constructs a verifyingRestoreOutput backed by inner.
func newVerifyingRestoreOutput(inner *fileSystemRestoreOutput) *verifyingRestoreOutput {
	return &verifyingRestoreOutput{
		inner:    inner,
		verifier: newOwnershipVerifier(),
	}
}

// --- restore.Output interface -----------------------------------------------

// Parallelizable reports whether the output supports parallel execution.
func (o *verifyingRestoreOutput) Parallelizable() bool {
	return o.inner.Parallelizable()
}

// BeginDirectory delegates to inner.
func (o *verifyingRestoreOutput) BeginDirectory(ctx context.Context, relativePath string, d fs.Directory) error {
	return o.inner.BeginDirectory(ctx, relativePath, d)
}

// FinishDirectory delegates to inner, then verifies the directory's attributes.
func (o *verifyingRestoreOutput) FinishDirectory(ctx context.Context, relativePath string, d fs.Directory) error {
	if err := o.inner.FinishDirectory(ctx, relativePath, d); err != nil {
		return err
	}
	absPath := filepath.Join(o.inner.TargetPath, filepath.FromSlash(relativePath))
	o.verifyEntry(absPath, d)
	return nil
}

// WriteFile delegates to inner, then verifies the file's attributes.
func (o *verifyingRestoreOutput) WriteFile(ctx context.Context, relativePath string, f fs.File, progressCb restore.FileWriteProgress) error {
	if err := o.inner.WriteFile(ctx, relativePath, f, progressCb); err != nil {
		return err
	}
	absPath := filepath.Join(o.inner.TargetPath, filepath.FromSlash(relativePath))
	o.verifyEntry(absPath, f)
	return nil
}

// FileExists delegates to inner.
func (o *verifyingRestoreOutput) FileExists(ctx context.Context, relativePath string, f fs.File) bool {
	return o.inner.FileExists(ctx, relativePath, f)
}

// CreateSymlink delegates to inner, then verifies the symlink's attributes.
func (o *verifyingRestoreOutput) CreateSymlink(ctx context.Context, relativePath string, e fs.Symlink) error {
	if err := o.inner.CreateSymlink(ctx, relativePath, e); err != nil {
		return err
	}
	absPath := filepath.Join(o.inner.TargetPath, filepath.FromSlash(relativePath))
	o.verifyEntry(absPath, e)
	return nil
}

// SymlinkExists delegates to inner.
func (o *verifyingRestoreOutput) SymlinkExists(ctx context.Context, relativePath string, e fs.Symlink) bool {
	return o.inner.SymlinkExists(ctx, relativePath, e)
}

// WriteDirEntry delegates to inner.
func (o *verifyingRestoreOutput) WriteDirEntry(ctx context.Context, relativePath string, de *snapshot.DirEntry, e fs.Directory) error {
	return o.inner.WriteDirEntry(ctx, relativePath, de, e)
}

// Close delegates to inner.
func (o *verifyingRestoreOutput) Close(ctx context.Context) error {
	return o.inner.Close(ctx)
}

// --- RestoreOutput extras ---------------------------------------------------

// Flush delegates to inner.
func (o *verifyingRestoreOutput) Flush() error {
	return o.inner.Flush()
}

// Terminate delegates to inner.
func (o *verifyingRestoreOutput) Terminate() error {
	return o.inner.Terminate()
}

// --- Verification helpers ---------------------------------------------------

// verifyEntry checks the ownership (and, for non-symlinks, the mode) of absPath
// against the values stored in the fs.Entry e.
//
// On Windows this is a no-op because chown is not supported there and kopia
// skips the chown call itself.
func (o *verifyingRestoreOutput) verifyEntry(absPath string, e fs.Entry) {
	if runtime.GOOS == "windows" {
		return
	}
	owner := e.Owner()
	o.verifier.checkOwnership(absPath, owner.UserID, owner.GroupID)

	// Symlinks on Linux do not support chmod; skip mode check for them.
	if _, isSymlink := e.(fs.Symlink); !isSymlink {
		o.verifier.checkMode(absPath, e.Mode().Perm())
	}
}

// statOwner is implemented in the platform-specific files:
//   - ownership_verifier_unix.go  (linux, darwin, freebsd, …)
//   - ownership_verifier_windows.go (windows — always returns 0, 0)
//
// The function signature uses uint32 to match fs.OwnerInfo.UserID / GroupID.
