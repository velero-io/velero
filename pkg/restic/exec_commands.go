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

package restic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/exec"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

const restoreProgressCheckInterval = 10 * time.Second
const backupProgressCheckInterval = 10 * time.Second

var fileSystem = filesystem.NewFileSystem()

type backupStatusLine struct {
	MessageType string `json:"message_type"`
	// seen in status lines
	TotalBytes int64 `json:"total_bytes"`
	BytesDone  int64 `json:"bytes_done"`
	// seen in summary line at the end
	TotalBytesProcessed int64 `json:"total_bytes_processed"`
}

// GetSnapshotID runs provided 'restic snapshots' command to get the ID of a snapshot
// and an error if a unique snapshot cannot be identified.
func GetSnapshotID(snapshotIDCmd *Command) (string, error) {
	stdout, stderr, err := exec.RunCommand(snapshotIDCmd.Cmd())
	if err != nil {
		return "", errors.Wrapf(err, "error running command, stderr=%s", stderr)
	}

	type snapshotID struct {
		ShortID string `json:"short_id"`
	}

	var snapshots []snapshotID
	if err := json.Unmarshal([]byte(stdout), &snapshots); err != nil {
		return "", errors.Wrap(err, "error unmarshaling restic snapshots result")
	}

	if len(snapshots) != 1 {
		return "", errors.Errorf("expected one matching snapshot by command: %s, got %d", snapshotIDCmd.String(), len(snapshots))
	}

	return snapshots[0].ShortID, nil
}

// RunBackup runs a `restic backup` command and watches the output to provide
// progress updates to the caller.
func RunBackup(backupCmd *Command, log logrus.FieldLogger, updater uploader.ProgressUpdater) (string, string, error) {
	// buffers for copying command stdout/err output into
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	// create a channel to signal when to end the goroutine scanning for progress
	// updates
	quit := make(chan struct{})

	cmd := backupCmd.Cmd()
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	err := cmd.Start()
	if err != nil {
		exec.LogErrorAsExitCode(err, log)
		return stdoutBuf.String(), stderrBuf.String(), err
	}

	go func() {
		ticker := time.NewTicker(backupProgressCheckInterval)
		for {
			select {
			case <-ticker.C:
				lastLine := getLastLine(stdoutBuf.Bytes())
				if len(lastLine) > 0 {
					stat, err := decodeBackupStatusLine(lastLine)
					if err != nil {
						log.WithError(err).Errorf("error getting restic backup progress")
					}

					// if the line contains a non-empty bytes_done field, we can update the
					// caller with the progress
					if stat.BytesDone != 0 {
						updater.UpdateProgress(&uploader.Progress{
							TotalBytes: stat.TotalBytes,
							BytesDone:  stat.BytesDone,
						})
					}
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	err = cmd.Wait()
	if err != nil {
		exec.LogErrorAsExitCode(err, log)
		return stdoutBuf.String(), stderrBuf.String(), err
	}
	quit <- struct{}{}

	summary, err := getSummaryLine(stdoutBuf.Bytes())
	if err != nil {
		return stdoutBuf.String(), stderrBuf.String(), err
	}
	stat, err := decodeBackupStatusLine(summary)
	if err != nil {
		return stdoutBuf.String(), stderrBuf.String(), err
	}
	if stat.MessageType != "summary" {
		return stdoutBuf.String(), stderrBuf.String(), errors.WithStack(fmt.Errorf("error getting restic backup summary: %s", string(summary)))
	}

	// update progress to 100%
	updater.UpdateProgress(&uploader.Progress{
		TotalBytes: stat.TotalBytesProcessed,
		BytesDone:  stat.TotalBytesProcessed,
	})

	return string(summary), stderrBuf.String(), nil
}

func decodeBackupStatusLine(lastLine []byte) (backupStatusLine, error) {
	var stat backupStatusLine
	if err := json.Unmarshal(lastLine, &stat); err != nil {
		return stat, errors.Wrapf(err, "unable to decode backup JSON line: %s", string(lastLine))
	}
	return stat, nil
}

// getLastLine returns the last line of a byte array. The string is assumed to
// have a newline at the end of it, so this returns the substring between the
// last two newlines.
func getLastLine(b []byte) []byte {
	if len(b) == 0 {
		return []byte("")
	}
	// subslice the byte array to ignore the newline at the end of the string
	lastNewLineIdx := bytes.LastIndex(b[:len(b)-1], []byte("\n"))
	return b[lastNewLineIdx+1 : len(b)-1]
}

// getSummaryLine looks for the summary JSON line
// (`{"message_type:"summary",...`) in the restic backup command output. Due to
// an issue in Restic, this might not always be the last line
// (https://github.com/restic/restic/issues/2389). It returns an error if it
// can't be found.
func getSummaryLine(b []byte) ([]byte, error) {
	summaryLineIdx := bytes.LastIndex(b, []byte(`{"message_type":"summary"`))
	if summaryLineIdx < 0 {
		return nil, errors.New("unable to find summary in restic backup command output")
	}
	// find the end of the summary line
	newLineIdx := bytes.Index(b[summaryLineIdx:], []byte("\n"))
	if newLineIdx < 0 {
		return nil, errors.New("unable to get summary line from restic backup command output")
	}
	return b[summaryLineIdx : summaryLineIdx+newLineIdx], nil
}

// RunRestore runs a `restic restore` command and monitors the volume size to
// provide progress updates to the caller.
func RunRestore(restoreCmd *Command, log logrus.FieldLogger, updater uploader.ProgressUpdater) (string, string, error) {
	insecureTLSFlag := ""

	for _, extraFlag := range restoreCmd.ExtraFlags {
		if strings.Contains(extraFlag, resticInsecureTLSFlag) {
			insecureTLSFlag = extraFlag
		}
	}

	snapshotSize, err := getSnapshotSize(restoreCmd.RepoIdentifier, restoreCmd.PasswordFile, restoreCmd.CACertFile, restoreCmd.Args[0], restoreCmd.Env, insecureTLSFlag)
	if err != nil {
		return "", "", errors.Wrap(err, "error getting snapshot size")
	}

	updater.UpdateProgress(&uploader.Progress{
		TotalBytes: snapshotSize,
	})

	// create a channel to signal when to end the goroutine scanning for progress
	// updates
	quit := make(chan struct{})

	go func() {
		ticker := time.NewTicker(restoreProgressCheckInterval)
		for {
			select {
			case <-ticker.C:
				volumeSize, err := getVolumeSize(restoreCmd.Dir)
				if err != nil {
					log.WithError(err).Errorf("error getting restic restore progress")
				}

				if volumeSize != 0 {
					updater.UpdateProgress(&uploader.Progress{
						TotalBytes: snapshotSize,
						BytesDone:  volumeSize,
					})
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	stdout, stderr, err := exec.RunCommandWithLog(restoreCmd.Cmd(), log)
	quit <- struct{}{}

	// update progress to 100%
	updater.UpdateProgress(&uploader.Progress{
		TotalBytes: snapshotSize,
		BytesDone:  snapshotSize,
	})

	return stdout, stderr, err
}

func getSnapshotSize(repoIdentifier, passwordFile, caCertFile, snapshotID string, env []string, insecureTLS string) (int64, error) {
	cmd := StatsCommand(repoIdentifier, passwordFile, snapshotID)
	cmd.Env = env
	cmd.CACertFile = caCertFile

	if len(insecureTLS) > 0 {
		cmd.ExtraFlags = append(cmd.ExtraFlags, insecureTLS)
	}

	stdout, stderr, err := exec.RunCommand(cmd.Cmd())
	if err != nil {
		return 0, errors.Wrapf(err, "error running command, stderr=%s", stderr)
	}

	var snapshotStats struct {
		TotalSize int64 `json:"total_size"`
	}

	if err := json.Unmarshal([]byte(stdout), &snapshotStats); err != nil {
		return 0, errors.Wrapf(err, "error unmarshaling restic stats result, stdout=%s", stdout)
	}

	return snapshotStats.TotalSize, nil
}

func getVolumeSize(path string) (int64, error) {
	var size int64

	files, err := fileSystem.ReadDir(path)
	if err != nil {
		return 0, errors.Wrapf(err, "error reading directory %s", path)
	}

	for _, file := range files {
		if file.IsDir() {
			s, err := getVolumeSize(fmt.Sprintf("%s/%s", path, file.Name()))
			if err != nil {
				return 0, err
			}
			size += s
		} else {
			size += file.Size()
		}
	}

	return size, nil
}
