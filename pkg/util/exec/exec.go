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

package exec

import (
	"bytes"
	"io"
	"os/exec"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
)

// RunCommand runs a command and returns its stdout, stderr, and its returned
// error (if any). If there are errors reading stdout or stderr, their return
// value(s) will contain the error as a string.
func RunCommand(cmd *exec.Cmd) (string, string, error) {
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	runErr := cmd.Run()

	var stdout, stderr string

	if res, readErr := io.ReadAll(stdoutBuf); readErr != nil {
		stdout = errors.Wrap(readErr, "error reading command's stdout").Error()
	} else {
		stdout = string(res)
	}

	if res, readErr := io.ReadAll(stderrBuf); readErr != nil {
		stderr = errors.Wrap(readErr, "error reading command's stderr").Error()
	} else {
		stderr = string(res)
	}

	return stdout, stderr, runErr
}

func RunCommandWithLog(cmd *exec.Cmd, log logrus.FieldLogger) (string, string, error) {
	stdout, stderr, err := RunCommand(cmd)
	LogErrorAsExitCode(err, log)
	return stdout, stderr, err
}

func LogErrorAsExitCode(err error, log logrus.FieldLogger) {
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			log.Errorf("Restic command fail with ExitCode: %d. Process ID is %d, Exit error is: %s", exitError.ExitCode(), exitError.Pid(), exitError.String())
			// Golang's os.exec -1 ExitCode means signal kill. Usually this is caused
			// by CGroup's OOM. Log a warning to notice user.
			// https://github.com/golang/go/blob/master/src/os/exec_posix.go#L128-L136
			if exitError.ExitCode() == -1 {
				log.Warnf("The ExitCode is -1, which means the process is terminated by signal. Usually this is caused by CGroup kill due to out of memory. Please check whether there is such information in the work nodes' dmesg log.")
			}
		} else {
			log.WithError(err).Info("Error cannot be convert to ExitError format.")
		}
	}
}
