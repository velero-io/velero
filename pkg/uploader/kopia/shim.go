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
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/content"
	"github.com/kopia/kopia/repo/content/index"
	"github.com/kopia/kopia/repo/manifest"
	"github.com/kopia/kopia/repo/object"
)

// shimRepository which is one adapter for unified repo and kopia.
// it implement kopia RepositoryWriter interfaces
type shimRepository struct {
	udmRepo udmrepo.BackupRepo
}

// shimObjectWriter object writer for unifited repo
type shimObjectWriter struct {
	repoWriter udmrepo.ObjectWriter
}

// shimObjectReader object reader for unifited repo
type shimObjectReader struct {
	repoReader udmrepo.ObjectReader
}

func NewShimRepo(repo udmrepo.BackupRepo) repo.RepositoryWriter {
	return &shimRepository{
		udmRepo: repo,
	}
}

// OpenObject open specific object
func (sr *shimRepository) OpenObject(ctx context.Context, id object.ID) (object.Reader, error) {
	reader, err := sr.udmRepo.OpenObject(ctx, udmrepo.ID(id.String()))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open object with id %v", id)
	}
	if reader == nil {
		return nil, err
	}

	return &shimObjectReader{
		repoReader: reader,
	}, err
}

// VerifyObject not supported
func (sr *shimRepository) VerifyObject(ctx context.Context, id object.ID) ([]content.ID, error) {
	return nil, errors.New("VerifyObject is not supported")
}

// Get one or more manifest data that match the specific manifest id
func (sr *shimRepository) GetManifest(ctx context.Context, id manifest.ID, payload any) (*manifest.EntryMetadata, error) {
	repoMani := udmrepo.RepoManifest{
		Payload: payload,
	}

	if err := sr.udmRepo.GetManifest(ctx, udmrepo.ID(id), &repoMani); err != nil {
		return nil, errors.Wrapf(err, "failed to get manifest with id %v", id)
	}
	return GetKopiaManifestEntry(repoMani.Metadata), nil
}

// Get one or more manifest data that match the given labels
func (sr *shimRepository) FindManifests(ctx context.Context, labels map[string]string) ([]*manifest.EntryMetadata, error) {
	metadata, err := sr.udmRepo.FindManifests(ctx, udmrepo.ManifestFilter{Labels: labels})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get manifests with labels %v", labels)
	}
	return GetKopiaManifestEntries(metadata), nil
}

// GetKopiaManifestEntry get metadata from specific ManifestEntryMetadata
func GetKopiaManifestEntry(uMani *udmrepo.ManifestEntryMetadata) *manifest.EntryMetadata {
	var ret manifest.EntryMetadata

	ret.ID = manifest.ID(uMani.ID)
	ret.Labels = uMani.Labels
	ret.Length = int(uMani.Length)
	ret.ModTime = uMani.ModTime

	return &ret
}

// GetKopiaManifestEntries get metadata list from specific ManifestEntryMetadata
func GetKopiaManifestEntries(uMani []*udmrepo.ManifestEntryMetadata) []*manifest.EntryMetadata {
	var ret []*manifest.EntryMetadata

	for _, entry := range uMani {
		var e manifest.EntryMetadata
		e.ID = manifest.ID(entry.ID)
		e.Labels = entry.Labels
		e.Length = int(entry.Length)
		e.ModTime = entry.ModTime

		ret = append(ret, &e)
	}

	return ret
}

// Time Get the local time of the unified repo
func (sr *shimRepository) Time() time.Time {
	return sr.udmRepo.Time()
}

// ClientOptions is not supported by unified repo
func (sr *shimRepository) ClientOptions() repo.ClientOptions {
	return repo.ClientOptions{}
}

// Refresh not supported
func (sr *shimRepository) Refresh(ctx context.Context) error {
	return errors.New("Refresh is not supported")
}

// ContentInfo not supported
func (sr *shimRepository) ContentInfo(ctx context.Context, contentID content.ID) (content.Info, error) {
	return index.Info{}, errors.New("ContentInfo is not supported")
}

// PrefetchContents is not supported by unified repo
func (sr *shimRepository) PrefetchContents(ctx context.Context, contentIDs []content.ID, hint string) []content.ID {
	return nil
}

// PrefetchObjects is not supported by unified repo
func (sr *shimRepository) PrefetchObjects(ctx context.Context, objectIDs []object.ID, hint string) ([]content.ID, error) {
	return nil, errors.New("PrefetchObjects is not supported")
}

// UpdateDescription is not supported by unified repo
func (sr *shimRepository) UpdateDescription(d string) {
}

// NewWriter is not supported by unified repo
func (sr *shimRepository) NewWriter(ctx context.Context, option repo.WriteSessionOptions) (context.Context, repo.RepositoryWriter, error) {
	return nil, nil, errors.New("NewWriter is not supported")
}

// Close will close unified repo
func (sr *shimRepository) Close(ctx context.Context) error {
	return sr.udmRepo.Close(ctx)
}

// NewObjectWriter creates an object writer
func (sr *shimRepository) NewObjectWriter(ctx context.Context, option object.WriterOptions) object.Writer {
	var opt udmrepo.ObjectWriteOptions
	opt.Description = option.Description
	opt.Prefix = udmrepo.ID(option.Prefix)
	opt.FullPath = ""
	opt.AccessMode = udmrepo.ObjectDataAccessModeFile
	opt.AsyncWrites = option.AsyncWrites

	if strings.HasPrefix(option.Description, "DIR:") {
		opt.DataType = udmrepo.ObjectDataTypeMetadata
	} else {
		opt.DataType = udmrepo.ObjectDataTypeData
	}

	writer, err := sr.udmRepo.NewObjectWriter(ctx, opt)
	if err != nil || writer == nil {
		return nil
	}

	return &shimObjectWriter{
		repoWriter: writer,
	}
}

// PutManifest saves the given manifest payload with a set of labels.
func (sr *shimRepository) PutManifest(ctx context.Context, labels map[string]string, payload any) (manifest.ID, error) {
	id, err := sr.udmRepo.PutManifest(ctx, udmrepo.RepoManifest{
		Payload: payload,
		Metadata: &udmrepo.ManifestEntryMetadata{
			Labels: labels,
		},
	})

	return manifest.ID(id), err
}

// DeleteManifest deletes the manifest with a given ID.
func (sr *shimRepository) DeleteManifest(ctx context.Context, id manifest.ID) error {
	return sr.udmRepo.DeleteManifest(ctx, udmrepo.ID(id))
}

func (sr *shimRepository) ReplaceManifests(ctx context.Context, labels map[string]string, payload any) (manifest.ID, error) {
	const minReplaceManifestTimeDelta = 100 * time.Millisecond

	md, err := sr.FindManifests(ctx, labels)
	if err != nil {
		return "", errors.Wrap(err, "unable to load manifests")
	}

	for _, em := range md {
		age := sr.Time().Sub(em.ModTime)
		if age < minReplaceManifestTimeDelta {
			time.Sleep(minReplaceManifestTimeDelta)
		}

		if err := sr.DeleteManifest(ctx, em.ID); err != nil {
			return "", errors.Wrapf(err, "unable to delete previous manifest %v", em.ID)
		}
	}

	return sr.PutManifest(ctx, labels, payload)
}

// Flush all the unifited repository data
func (sr *shimRepository) Flush(ctx context.Context) error {
	return sr.udmRepo.Flush(ctx)
}

func (sr *shimRepository) ConcatenateObjects(ctx context.Context, objectIDs []object.ID, opt repo.ConcatenateOptions) (object.ID, error) {
	if len(objectIDs) == 0 {
		return object.EmptyID, errors.New("object list is empty")
	}

	ids := []udmrepo.ID{}
	for _, id := range objectIDs {
		ids = append(ids, udmrepo.ID(id.String()))
	}

	id, err := sr.udmRepo.ConcatenateObjects(ctx, ids)
	if err != nil {
		return object.EmptyID, err
	}

	return object.ParseID(string(id))
}

func (sr *shimRepository) OnSuccessfulFlush(callback repo.RepositoryWriterCallback) {
}

// Flush all the unifited repository data
func (sr *shimObjectReader) Read(p []byte) (n int, err error) {
	return sr.repoReader.Read(p)
}

func (sr *shimObjectReader) Seek(offset int64, whence int) (int64, error) {
	return sr.repoReader.Seek(offset, whence)
}

// Close current io for ObjectReader
func (sr *shimObjectReader) Close() error {
	return sr.repoReader.Close()
}

// Length returns the logical size of the object
func (sr *shimObjectReader) Length() int64 {
	return sr.repoReader.Length()
}

// Write data
func (sr *shimObjectWriter) Write(p []byte) (n int, err error) {
	return sr.repoWriter.Write(p)
}

// Periodically called to preserve the state of data written to the repo so far.
func (sr *shimObjectWriter) Checkpoint() (object.ID, error) {
	id, err := sr.repoWriter.Checkpoint()
	if err != nil {
		return object.ID{}, err
	}

	objID, err := object.ParseID(string(id))
	if err != nil {
		return object.ID{}, errors.Wrapf(err, "error to parse object ID from %v", id)
	}

	return objID, err
}

// Result returns the object's unified identifier after the write completes.
func (sr *shimObjectWriter) Result() (object.ID, error) {
	id, err := sr.repoWriter.Result()
	if err != nil {
		return object.ID{}, err
	}

	objID, err := object.ParseID(string(id))
	if err != nil {
		return object.ID{}, errors.Wrapf(err, "error to parse object ID from %v", id)
	}

	return objID, err
}

// Close closes the repository and releases all resources.
func (sr *shimObjectWriter) Close() error {
	return sr.repoWriter.Close()
}
