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

package process

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
)

type RestartableProcessFactory interface {
	NewRestartableProcess(command string, logger logrus.FieldLogger, logLevel logrus.Level) (RestartableProcess, error)
}

type restartableProcessFactory struct {
}

func NewRestartableProcessFactory() RestartableProcessFactory {
	return &restartableProcessFactory{}
}

func (rpf *restartableProcessFactory) NewRestartableProcess(command string, logger logrus.FieldLogger, logLevel logrus.Level) (RestartableProcess, error) {
	return newRestartableProcess(command, logger, logLevel)
}

type RestartableProcess interface {
	AddReinitializer(key KindAndName, r Reinitializer)
	Reset() error
	ResetIfNeeded() error
	GetByKindAndName(key KindAndName) (any, error)
	Stop()
}

// restartableProcess encapsulates the lifecycle for all plugins contained in a single executable file. It is able
// to restart a plugin process if it is terminated for any reason. If this happens, all plugins are reinitialized using
// the original configuration data.
type restartableProcess struct {
	command  string
	logger   logrus.FieldLogger
	logLevel logrus.Level

	// lock guards all of the fields below
	lock           sync.RWMutex
	process        Process
	plugins        map[KindAndName]any
	reinitializers map[KindAndName]Reinitializer
	resetFailures  int
}

// reinitializer is capable of reinitializing a restartable plugin instance using the newly dispensed plugin.
type Reinitializer interface {
	// reinitialize reinitializes a restartable plugin instance using the newly dispensed plugin.
	Reinitialize(dispensed any) error
}

// newRestartableProcess creates a new restartableProcess for the given command and options.
func newRestartableProcess(command string, logger logrus.FieldLogger, logLevel logrus.Level) (RestartableProcess, error) {
	p := &restartableProcess{
		command:        command,
		logger:         logger,
		logLevel:       logLevel,
		plugins:        make(map[KindAndName]any),
		reinitializers: make(map[KindAndName]Reinitializer),
	}

	// This launches the process
	err := p.Reset()

	return p, err
}

// AddReinitializer registers the reinitializer r for key.
func (p *restartableProcess) AddReinitializer(key KindAndName, r Reinitializer) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.reinitializers[key] = r
}

// Reset acquires the lock and calls resetLH.
func (p *restartableProcess) Reset() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	return p.resetLH()
}

// resetLH (re)launches the plugin process. It redispenses all previously dispensed plugins and reinitializes all the
// registered reinitializers using the newly dispensed plugins.
//
// Callers of resetLH *must* acquire the lock before calling it.
func (p *restartableProcess) resetLH() error {
	if p.resetFailures > 10 {
		return errors.Errorf("unable to restart plugin process: exceeded maximum number of reset failures")
	}

	process, err := newProcess(p.command, p.logger, p.logLevel)
	if err != nil {
		p.resetFailures++
		return err
	}
	p.process = process

	// Redispense any previously dispensed plugins, reinitializing if necessary.
	// Start by creating a new map to hold the newly dispensed plugins.
	newPlugins := make(map[KindAndName]any)
	for key := range p.plugins {
		// Re-dispense
		dispensed, err := p.process.dispense(key)
		if err != nil {
			p.resetFailures++
			return err
		}
		// Store in the new map
		newPlugins[key] = dispensed

		// Reinitialize
		if r, found := p.reinitializers[key]; found {
			if err := r.Reinitialize(dispensed); err != nil {
				p.resetFailures++
				return err
			}
		}
	}

	// Make sure we update p's plugins!
	p.plugins = newPlugins

	p.resetFailures = 0

	return nil
}

// ResetIfNeeded checks if the plugin process has exited and resets p if it has.
func (p *restartableProcess) ResetIfNeeded() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.process.exited() {
		p.logger.Info("Plugin process exited - restarting.")
		return p.resetLH()
	}

	return nil
}

// GetByKindAndName acquires the lock and calls getByKindAndNameLH.
func (p *restartableProcess) GetByKindAndName(key KindAndName) (any, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	return p.getByKindAndNameLH(key)
}

// getByKindAndNameLH returns the dispensed plugin for key. If the plugin hasn't been dispensed before, it dispenses a
// new one.
func (p *restartableProcess) getByKindAndNameLH(key KindAndName) (any, error) {
	dispensed, found := p.plugins[key]
	if found {
		return dispensed, nil
	}

	dispensed, err := p.process.dispense(key)
	if err != nil {
		return nil, err
	}
	p.plugins[key] = dispensed
	return p.plugins[key], nil
}

// stop terminates the plugin process.
func (p *restartableProcess) Stop() {
	p.lock.Lock()
	p.process.kill()
	p.lock.Unlock()
}
