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
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/velero-io/velero/pkg/uploader"

	"github.com/kopia/kopia/snapshot/upload"
)

// Throttle throttles controlle the interval of output result
type Throttle struct {
	throttle int64
	interval time.Duration
}

func (t *Throttle) ShouldOutput() bool {
	nextOutputTimeUnixNano := atomic.LoadInt64(&t.throttle)
	if nowNano := time.Now().UnixNano(); nowNano > nextOutputTimeUnixNano {
		if atomic.CompareAndSwapInt64(&t.throttle, nextOutputTimeUnixNano, nowNano+t.interval.Nanoseconds()) {
			return true
		}
	}
	return false
}

// Progress represents a backup or restore counters.
type Progress struct {
	// all int64 must precede all int32 due to alignment requirements on ARM
	// +checkatomic
	uploadedBytes int64 //the total bytes has uploaded
	cachedBytes   int64 //the total bytes has cached
	hashededBytes int64 //the total bytes has hashed
	// +checkatomic
	uploadedFiles int32 //the total files has ignored
	// +checkatomic
	ignoredErrorCount int32 //the total errors has ignored
	// +checkatomic
	fatalErrorCount     int32 //the total errors has occurred
	estimatedFileCount  int64 // +checklocksignore the total count of files to be processed
	estimatedTotalBytes int64 // +checklocksignore	the total size of files to be processed
	// +checkatomic
	processedBytes  int64                    // which statistic all bytes has been processed currently
	outputThrottle  Throttle                 // which control the frequency of update progress
	updater         uploader.ProgressUpdater //which kopia progress will call the UpdateProgress interface, the third party will implement the interface to do the progress update
	log             logrus.FieldLogger       // output info into log when backup
	estimationParam upload.EstimationParameters
}

func NewProgress(updater uploader.ProgressUpdater, interval time.Duration, log logrus.FieldLogger) *Progress {
	return &Progress{
		outputThrottle: Throttle{
			throttle: 0,
			interval: interval,
		},
		updater: updater,
		estimationParam: upload.EstimationParameters{
			Type:              upload.EstimationTypeClassic,
			AdaptiveThreshold: 300000,
		},
		log: log,
	}
}

// UploadedBytes the total bytes has uploaded currently
func (p *Progress) UploadedBytes(numBytes int64) {
	atomic.AddInt64(&p.uploadedBytes, numBytes)
	atomic.AddInt32(&p.uploadedFiles, 1)

	p.UpdateProgress()
}

// Error statistic the total Error has occurred
func (p *Progress) Error(path string, err error, isIgnored bool) {
	if isIgnored {
		atomic.AddInt32(&p.ignoredErrorCount, 1)
		p.log.Warnf("Ignored error when processing %v: %v", path, err)
	} else {
		atomic.AddInt32(&p.fatalErrorCount, 1)
		p.log.Errorf("Error when processing %v: %v", path, err)
	}
}

// EstimatedDataSize statistic the total size of files to be processed and total files to be processed
func (p *Progress) EstimatedDataSize(fileCount int64, totalBytes int64) {
	atomic.StoreInt64(&p.estimatedTotalBytes, totalBytes)
	atomic.StoreInt64(&p.estimatedFileCount, fileCount)

	p.UpdateProgress()
}

// UpdateProgress which calls Updater UpdateProgress interface, update progress by third-party implementation
func (p *Progress) UpdateProgress() {
	if p.outputThrottle.ShouldOutput() {
		p.updater.UpdateProgress(&uploader.Progress{TotalBytes: p.estimatedTotalBytes, BytesDone: p.processedBytes})
	}
}

// UploadStarted statistic the total Error has occurred
func (p *Progress) UploadStarted() {}

// CachedFile statistic the total bytes been cached currently
func (p *Progress) CachedFile(fname string, numBytes int64) {
	atomic.AddInt64(&p.cachedBytes, numBytes)
	atomic.AddInt64(&p.processedBytes, numBytes)
	p.UpdateProgress()
}

// HashedBytes statistic the total bytes been hashed currently
func (p *Progress) HashedBytes(numBytes int64) {
	atomic.AddInt64(&p.processedBytes, numBytes)
	atomic.AddInt64(&p.hashededBytes, numBytes)
	p.UpdateProgress()
}

// HashingFile statistic the file been hashed currently
func (p *Progress) HashingFile(fname string) {}

// ExcludedFile statistic the file been excluded currently
func (p *Progress) ExcludedFile(fname string, numBytes int64) {}

// ExcludedDir statistic the dir been excluded currently
func (p *Progress) ExcludedDir(dirname string) {
	p.log.Infof("Excluded dir %s", dirname)
}

// FinishedHashingFile which will called when specific file finished hash
func (p *Progress) FinishedHashingFile(fname string, numBytes int64) {
	p.UpdateProgress()
}

// StartedDirectory called when begin to upload one directory
func (p *Progress) StartedDirectory(dirname string) {}

// FinishedDirectory called when finish to upload one directory
func (p *Progress) FinishedDirectory(dirname string) {
	p.UpdateProgress()
}

// UploadFinished which report the files flushed after the Upload has completed.
func (p *Progress) UploadFinished() {
	p.UpdateProgress()
}

// ProgressBytes which statistic all bytes has been processed currently
func (p *Progress) ProgressBytes(processedBytes int64, totalBytes int64) {
	atomic.StoreInt64(&p.processedBytes, processedBytes)
	atomic.StoreInt64(&p.estimatedTotalBytes, totalBytes)
	p.UpdateProgress()
}

func (p *Progress) FinishedFile(fname string, err error) {}

func (p *Progress) EstimationParameters() upload.EstimationParameters {
	return p.estimationParam
}

func (p *Progress) Enabled() bool {
	return true
}

func (p *Progress) GetIncrementalSize() int64 {
	return p.estimatedTotalBytes - p.cachedBytes
}
