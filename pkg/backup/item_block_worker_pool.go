/*
Copyright the Velero Contributors.

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

package backup

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ItemBlockWorkerPool struct {
	inputChannel chan ItemBlockInput
	wg           *sync.WaitGroup
	logger       logrus.FieldLogger
	cancelFunc   context.CancelFunc
}

type ItemBlockInput struct {
	itemBlock  *BackupItemBlock
	returnChan chan ItemBlockReturn
}

type ItemBlockReturn struct {
	itemBlock *BackupItemBlock
	resources []schema.GroupResource
	err       error
}

func (p *ItemBlockWorkerPool) GetInputChannel() chan ItemBlockInput {
	return p.inputChannel
}

func StartItemBlockWorkerPool(ctx context.Context, workers int, log logrus.FieldLogger) *ItemBlockWorkerPool {
	// Buffer will hold up to 10 ItemBlocks waiting for processing
	inputChannel := make(chan ItemBlockInput, max(workers, 10))

	ctx, cancelFunc := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}

	for i := range workers {
		logger := log.WithField("worker", i)
		wg.Add(1)
		go processItemBlockWorker(ctx, inputChannel, logger, wg)
	}

	pool := &ItemBlockWorkerPool{
		inputChannel: inputChannel,
		cancelFunc:   cancelFunc,
		logger:       log,
		wg:           wg,
	}
	return pool
}

func (p *ItemBlockWorkerPool) Stop() {
	p.cancelFunc()
	p.logger.Info("ItemBlock worker stopping")
	p.wg.Wait()
	p.logger.Info("ItemBlock worker stopped")
}

func processItemBlockWorker(ctx context.Context,
	inputChannel chan ItemBlockInput,
	logger logrus.FieldLogger,
	wg *sync.WaitGroup) {
	for {
		select {
		case m := <-inputChannel:
			logger.Infof("processing ItemBlock for backup %v", m.itemBlock.itemBackupper.backupRequest.Name)
			grList := m.itemBlock.itemBackupper.kubernetesBackupper.backupItemBlock(m.itemBlock)
			logger.Infof("finished processing ItemBlock for backup %v", m.itemBlock.itemBackupper.backupRequest.Name)
			m.returnChan <- ItemBlockReturn{
				itemBlock: m.itemBlock,
				resources: grList,
				err:       nil,
			}
		case <-ctx.Done():
			logger.Info("stopping ItemBlock worker")
			wg.Done()
			return
		}
	}
}
