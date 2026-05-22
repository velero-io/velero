/*
Copyright 2018 the Velero contributors.

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
package restic

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackupCommand(t *testing.T) {
	c := BackupCommand("repo-id", "password-file", "path", map[string]string{"foo": "bar", "c": "d"})

	assert.Equal(t, "backup", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
	assert.Equal(t, "password-file", c.PasswordFile)
	assert.Equal(t, "path", c.Dir)
	assert.Equal(t, []string{"."}, c.Args)

	expected := []string{"--tag=foo=bar", "--tag=c=d", "--host=velero", "--json"}
	sort.Strings(expected)
	sort.Strings(c.ExtraFlags)
	assert.Equal(t, expected, c.ExtraFlags)
}

func TestRestoreCommand(t *testing.T) {
	c := RestoreCommand("repo-id", "password-file", "snapshot-id", "target")

	assert.Equal(t, "restore", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
	assert.Equal(t, "password-file", c.PasswordFile)
	assert.Equal(t, "target", c.Dir)
	assert.Equal(t, []string{"snapshot-id"}, c.Args)
	assert.Equal(t, []string{"--target=."}, c.ExtraFlags)
}

func TestGetSnapshotCommand(t *testing.T) {
	expectedTags := map[string]string{"foo": "bar", "c": "d"}
	c := GetSnapshotCommand("repo-id", "password-file", expectedTags)

	assert.Equal(t, "snapshots", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
	assert.Equal(t, "password-file", c.PasswordFile)

	// set up expected flag names
	expectedFlags := []string{"--json", "--latest=1", "--tag"}
	// for tracking actual flag names
	actualFlags := []string{}
	// for tracking actual --tag values as a map
	actualTags := make(map[string]string)

	// loop through actual flags
	for _, flag := range c.ExtraFlags {
		// split into 2 parts from the first = sign (if any)
		parts := strings.SplitN(flag, "=", 2)

		// convert --tag data to a map
		if parts[0] == "--tag" {
			actualFlags = append(actualFlags, parts[0])

			// split based on ,
			tags := strings.SplitSeq(parts[1], ",")
			// loop through each key-value tag pair
			for tag := range tags {
				// split the pair on =
				kvs := strings.Split(tag, "=")
				// record actual key & value
				actualTags[kvs[0]] = kvs[1]
			}
		} else {
			actualFlags = append(actualFlags, flag)
		}
	}

	assert.Equal(t, expectedFlags, actualFlags)
	assert.Equal(t, expectedTags, actualTags)
}

func TestInitCommand(t *testing.T) {
	c := InitCommand("repo-id")

	assert.Equal(t, "init", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
}

func TestSnapshotsCommand(t *testing.T) {
	c := SnapshotsCommand("repo-id")

	assert.Equal(t, "snapshots", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
}

func TestPruneCommand(t *testing.T) {
	c := PruneCommand("repo-id")

	assert.Equal(t, "prune", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
}

func TestForgetCommand(t *testing.T) {
	c := ForgetCommand("repo-id", "snapshot-id")

	assert.Equal(t, "forget", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
	assert.Equal(t, []string{"snapshot-id"}, c.Args)
}

func TestStatsCommand(t *testing.T) {
	c := StatsCommand("repo-id", "password-file", "snapshot-id")

	assert.Equal(t, "stats", c.Command)
	assert.Equal(t, "repo-id", c.RepoIdentifier)
	assert.Equal(t, "password-file", c.PasswordFile)
	assert.Equal(t, []string{"snapshot-id"}, c.Args)
	assert.Equal(t, []string{"--json"}, c.ExtraFlags)
}
