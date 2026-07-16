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

// Package datamover holds the shared data mover type identifiers and helpers.
// It must remain a leaf package (stdlib-only imports) so it can be referenced
// from anywhere in the codebase without introducing import cycles.
package datamover

const (
	// DataMoverTypeVelero refers to the default built-in data mover. The default
	// data mover may change among releases; see GetDefaultBuiltInDataMover.
	DataMoverTypeVelero = "velero"
	// DataMoverTypeVeleroFs refers to the Velero file system data mover.
	DataMoverTypeVeleroFs = "velero-fs"
	// DataMoverTypeVeleroBlock refers to the Velero block data mover.
	DataMoverTypeVeleroBlock = "velero-block"
)

// IsBuiltInDataMover reports whether the given data mover value refers to a
// Velero built-in data mover (an empty value or the default "velero" alias).
func IsBuiltInDataMover(dataMover string) bool {
	return dataMover == "" || dataMover == DataMoverTypeVelero
}

// GetDefaultBuiltInDataMover returns the data mover used when the default
// built-in data mover ("velero"/empty) is selected. The default may change
// between releases; currently it is the file system data mover.
func GetDefaultBuiltInDataMover() string {
	return DataMoverTypeVeleroFs
}
