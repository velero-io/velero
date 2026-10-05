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

package logging

import (
	"compress/gzip"
	"io"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
)

// DualModeLogger is a thread safe logger interface to write logs to dual targets, one of which
// is a persist file, so that the log could be further transferred.
type DualModeLogger interface {
	logrus.FieldLogger
	// DoneForPersist stops outputting logs to the persist file
	DoneForPersist(log logrus.FieldLogger)
	// GetPersistFile moves the persist file pointer to beginning and returns it
	GetPersistFile() (*os.File, error)
	// Dispose closes the temp file pointer and removes the file
	Dispose(log logrus.FieldLogger)
}

type tempFileLogger struct {
	logrus.FieldLogger
	logger *logrus.Logger
	file   *os.File
	w      *gzip.Writer
}

// NewTempFileLogger creates a DualModeLogger instance that writes logs to both Stdout and a file in the temp folder.
func NewTempFileLogger(logLevel logrus.Level, logFormat Format, hook *LogHook, fields logrus.Fields) (DualModeLogger, error) {
	file, err := os.CreateTemp("", "")
	if err != nil {
		return nil, errors.Wrap(err, "error creating temp file")
	}

	w := gzip.NewWriter(file)

	logger := DefaultLogger(logLevel, logFormat)
	logger.Out = io.MultiWriter(os.Stdout, w)

	if hook != nil {
		logger.Hooks.Add(hook)
	}

	return &tempFileLogger{
		FieldLogger: logger.WithFields(fields),
		logger:      logger,
		file:        file,
		w:           w,
	}, nil
}

func (p *tempFileLogger) DoneForPersist(log logrus.FieldLogger) {
	p.logger.SetOutput(os.Stdout)

	if err := p.w.Close(); err != nil {
		log.WithError(err).Warn("error closing gzip writer")
	}
}

func (p *tempFileLogger) GetPersistFile() (*os.File, error) {
	if _, err := p.file.Seek(0, 0); err != nil {
		return nil, errors.Wrap(err, "error resetting log file offset to 0")
	}

	return p.file, nil
}

func (p *tempFileLogger) Dispose(log logrus.FieldLogger) {
	p.w.Close()
	closeAndRemoveFile(p.file, log)
}

func closeAndRemoveFile(file *os.File, log logrus.FieldLogger) {
	if file == nil {
		log.Debug("Skipping removal of temp log file due to nil file pointer")
		return
	}
	if err := file.Close(); err != nil {
		log.WithError(err).WithField("file", file.Name()).Warn("error closing temp log file")
	}
	if err := os.Remove(file.Name()); err != nil {
		log.WithError(err).WithField("file", file.Name()).Warn("error removing temp log file")
	}
}
