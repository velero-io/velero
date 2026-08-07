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
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kopia/kopia/snapshot/restore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// ownershipVerifier unit tests
// --------------------------------------------------------------------------

func TestNewOwnershipVerifier(t *testing.T) {
	v := newOwnershipVerifier()
	require.NotNil(t, v)
	assert.Equal(t, int64(0), v.MismatchCount())
	assert.Empty(t, v.Samples())
}

func TestOwnershipVerifier_record_incrementsCounter(t *testing.T) {
	v := newOwnershipVerifier()
	v.record(AttrMismatch{Path: "/a", ExpectedUID: 1000})
	v.record(AttrMismatch{Path: "/b", ExpectedUID: 2000})

	assert.Equal(t, int64(2), v.MismatchCount())
}

func TestOwnershipVerifier_record_capsAt_maxSamples(t *testing.T) {
	v := newOwnershipVerifier()
	// Record more entries than the cap.
	for i := range maxAttrMismatchSamples + 5 {
		v.record(AttrMismatch{Path: fmt.Sprintf("/file%d", i)})
	}

	assert.Equal(t, int64(maxAttrMismatchSamples+5), v.MismatchCount())
	// Sample list must never exceed the cap.
	samples := v.Samples()
	assert.Len(t, samples, maxAttrMismatchSamples)
}

func TestOwnershipVerifier_Samples_returnsCopy(t *testing.T) {
	v := newOwnershipVerifier()
	v.record(AttrMismatch{Path: "/original"})

	s1 := v.Samples()
	s1[0].Path = "/mutated" // mutating the returned slice

	s2 := v.Samples()
	assert.Equal(t, "/original", s2[0].Path, "Samples() must return an independent copy")
}

// --------------------------------------------------------------------------
// AttrMismatch.String unit tests
// --------------------------------------------------------------------------

func TestAttrMismatch_String_ownershipOnly(t *testing.T) {
	m := AttrMismatch{
		Path:        "/data/secret",
		ExpectedUID: 1000,
		ExpectedGID: 2000,
		ActualUID:   0,
		ActualGID:   0,
	}
	s := m.String()
	assert.Contains(t, s, "/data/secret")
	assert.Contains(t, s, "1000")
	assert.Contains(t, s, "2000")
}

func TestAttrMismatch_String_modeOnly(t *testing.T) {
	m := AttrMismatch{
		Path:         "/data/file",
		ExpectedMode: 0o755,
		ActualMode:   0o644,
	}
	s := m.String()
	assert.Contains(t, s, "/data/file")
	assert.Contains(t, s, "755")
	assert.Contains(t, s, "644")
}

// --------------------------------------------------------------------------
// checkOwnership / checkMode behaviour tests using real temp files
// --------------------------------------------------------------------------

func TestOwnershipVerifier_checkOwnership_noMismatch(t *testing.T) {
	// Create a real temp file and lstat it; the owner will be the current user,
	// so calling checkOwnership with the actual uid/gid should record nothing.
	f, err := os.CreateTemp(t.TempDir(), "velero-ownership-test-*")
	require.NoError(t, err)
	f.Close()

	info, err := os.Lstat(f.Name())
	require.NoError(t, err)

	uid, gid := statOwner(info)

	v := newOwnershipVerifier()
	v.checkOwnership(f.Name(), uid, gid)

	assert.Equal(t, int64(0), v.MismatchCount(), "same uid/gid must not produce a mismatch")
}

func TestOwnershipVerifier_checkOwnership_mismatchRecorded(t *testing.T) {
	if os.Getuid() == 0 {
		// Running as root; ownership checks behave differently — skip.
		t.Skip("skipping ownership mismatch test when running as root")
	}

	f, err := os.CreateTemp(t.TempDir(), "velero-ownership-test-*")
	require.NoError(t, err)
	f.Close()

	v := newOwnershipVerifier()
	// Pass deliberately wrong expected values (uid 99999 is unlikely to match).
	v.checkOwnership(f.Name(), 99999, 99999)

	assert.Equal(t, int64(1), v.MismatchCount(), "wrong uid/gid should be recorded as a mismatch")
	samples := v.Samples()
	require.Len(t, samples, 1)
	assert.Equal(t, f.Name(), samples[0].Path)
	assert.Equal(t, uint32(99999), samples[0].ExpectedUID)
}

func TestOwnershipVerifier_checkMode_noMismatch(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "velero-mode-test-*")
	require.NoError(t, err)
	f.Close()

	// Chmod to a known mode first, then verify with the same mode.
	target := os.FileMode(0o640)
	require.NoError(t, os.Chmod(f.Name(), target))

	v := newOwnershipVerifier()
	v.checkMode(f.Name(), target)

	assert.Equal(t, int64(0), v.MismatchCount(), "matching mode must not produce a mismatch")
}

func TestOwnershipVerifier_checkMode_mismatchRecorded(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "velero-mode-test-*")
	require.NoError(t, err)
	f.Close()

	require.NoError(t, os.Chmod(f.Name(), 0o644))

	v := newOwnershipVerifier()
	// Pass a different mode than what was set.
	v.checkMode(f.Name(), 0o700)

	assert.Equal(t, int64(1), v.MismatchCount())
	samples := v.Samples()
	require.Len(t, samples, 1)
	assert.Equal(t, os.FileMode(0o700), samples[0].ExpectedMode)
	assert.Equal(t, os.FileMode(0o644), samples[0].ActualMode)
}

func TestOwnershipVerifier_checkOwnership_nonExistentFile(t *testing.T) {
	v := newOwnershipVerifier()
	// A non-existent path should not panic and should not be recorded.
	v.checkOwnership("/nonexistent/path/that/does/not/exist", 1000, 1000)
	assert.Equal(t, int64(0), v.MismatchCount())
}

func TestOwnershipVerifier_checkMode_nonExistentFile(t *testing.T) {
	v := newOwnershipVerifier()
	v.checkMode("/nonexistent/path", 0o755)
	assert.Equal(t, int64(0), v.MismatchCount())
}

// --------------------------------------------------------------------------
// verifyingRestoreOutput unit tests
// --------------------------------------------------------------------------

// TestVerifyingRestoreOutput_verifyEntry_ownershipMismatch simulates a file
// whose ownership does not match after restore (as happens on NFS root_squash
// or SMB fake-success). It uses a real temp file with a deliberately mismatched
// expected UID so that checkOwnership records the mismatch.
func TestVerifyingRestoreOutput_verifyEntry_ownershipMismatch(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping ownership mismatch test when running as root")
	}

	dir := t.TempDir()
	path := dir + "/testfile"
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))

	v := newOwnershipVerifier()
	// Simulate a mismatch: pass uid 99999 which won't match the actual owner.
	v.checkOwnership(path, 99999, 99999)

	assert.Equal(t, int64(1), v.MismatchCount())
	samples := v.Samples()
	require.Len(t, samples, 1)
	assert.Equal(t, path, samples[0].Path)
}

// TestNewVerifyingRestoreOutput_initState checks that the constructor properly wires the
// inner fileSystemRestoreOutput and initialises the verifier.
func TestNewVerifyingRestoreOutput_initState(t *testing.T) {
	inner := &fileSystemRestoreOutput{
		FilesystemOutput: &restore.FilesystemOutput{
			TargetPath: t.TempDir(),
		},
	}
	vOut := newVerifyingRestoreOutput(inner)

	require.NotNil(t, vOut)
	require.NotNil(t, vOut.verifier)
	assert.Equal(t, int64(0), vOut.verifier.MismatchCount())
}

// --------------------------------------------------------------------------
// concurrent safety smoke test
// --------------------------------------------------------------------------

func TestOwnershipVerifier_concurrentRecords(t *testing.T) {
	v := newOwnershipVerifier()
	const goroutines = 50

	done := make(chan struct{})
	for range goroutines {
		go func() {
			v.record(AttrMismatch{Path: "/concurrent/file"})
			done <- struct{}{}
		}()
	}
	for range goroutines {
		<-done
	}

	assert.Equal(t, int64(goroutines), v.MismatchCount())
	samples := v.Samples()
	assert.LessOrEqual(t, len(samples), maxAttrMismatchSamples)
}


// TestAttrMismatchString_full exercises all fields of the String() formatter.
func TestAttrMismatch_String_full(t *testing.T) {
	m := AttrMismatch{
		Path:         "/etc/passwd",
		ExpectedUID:  0,
		ExpectedGID:  0,
		ActualUID:    1000,
		ActualGID:    1000,
		ExpectedMode: 0o644,
		ActualMode:   0o600,
	}
	s := m.String()
	// All key tokens must appear in the output.
	for _, want := range []string{"/etc/passwd", "0:0", "1000:1000", "644", "600"} {
		assert.True(t, strings.Contains(s, want), "String() missing %q in %q", want, s)
	}
}
