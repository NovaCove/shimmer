package transform

import (
	"io/fs"
	"log/slog"
	"os"

	"github.com/NovaCove/grainfs"
	"github.com/NovaCove/shimmer/lib/server/config"
	"github.com/NovaCove/shimmer/lib/server/secure/internaldata"
	"github.com/NovaCove/shimmer/lib/server/secure/keymanagement"
	"github.com/go-git/go-billy/v5/osfs"
)

// Ingestor is how we take an existing filesystem directory and transform it into an encrypted
// filesystem that can be used by the NFS system to then mount and serve files. The normal process
// is as follows:
//  1. Ingestor is created with the source directory location, the destination directory location,
//     and a reference to the internaldata package which contains the ability to create or retrieve
//     encryption keys, as well as storing metadata about the files.
//  2. The Ingestor reads the source directory, encrypts the files, and writes them to the
//     destination directory. It also stores metadata about the files in the internaldata package.
type Ingestor interface {
	Init() error
	Ingest() error
}

type ingestor struct {
	name         string
	sourceDir    string
	destDir      string
	internalData internaldata.InternalData // Reference to the internaldata package for key management and metadata storage
	skm          *keymanagement.SecureKeychainManager
	fs           *grainfs.GrainFS

	lgr *slog.Logger // Logger for the ingestor, if needed
}

func NewIngestor(
	name, sourceDir, destDir string,
	internalData internaldata.InternalData,
	skm *keymanagement.SecureKeychainManager,
	lgr *slog.Logger,
) Ingestor {
	return &ingestor{
		name:         name,
		sourceDir:    sourceDir,
		destDir:      destDir,
		internalData: internalData,
		skm:          skm,
		lgr:          lgr,
	}
}

func (i *ingestor) Init() error {
	// Ensure that the destination directory doesn't exist or is empty.
	i.lgr.Debug("Initializing ingestor", "name", i.name, "sourceDir", i.sourceDir, "destDir", i.destDir)
	if _, err := os.Stat(i.destDir); err == nil {
		return fs.ErrExist // Destination directory already exists, cannot overwrite.
	}

	i.lgr.Debug("Generating encryption key for ingestor", "name", i.name)
	key, err := i.skm.GenerateEncryptionKey(i.name, 64)
	if err != nil {
		return err
	}

	i.lgr.Debug("Creating encrypted filesystem destination dir", "destDir", i.destDir)
	if err := os.MkdirAll(i.destDir, 0700); err != nil {
		return err
	}

	i.lgr.Debug("Creating encrypted filesystem", "destDir", i.destDir)
	ofs := osfs.New(i.destDir)
	i.fs, err = grainfs.New(ofs, key)
	return err
}

func (i *ingestor) Ingest() error {
	i.lgr.Debug("Creating ingest source tree to walk", "sourceDir", i.sourceDir)
	srcTree := os.DirFS(i.sourceDir)
	i.lgr.Debug("Starting to walk source directory", "sourceDir", i.sourceDir)
	if err := fs.WalkDir(srcTree, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			i.lgr.Debug("Creating directory", "path", path)
			return i.fs.MkdirAll(path, 0700)
		}

		i.lgr.Debug("Processing file", "path", path)
		data, err := fs.ReadFile(srcTree, path)
		if err != nil {
			i.lgr.Error("Error reading file", "path", path, "error", err)
			return err
		}

		if n, err := i.fs.Write(path, data); err != nil {
			i.lgr.Error("Error writing file to encrypted filesystem", "path", path, "error", err)
			return err
		} else if n != len(data) {
			i.lgr.Error("Incomplete write to encrypted filesystem", "path", path, "expected", len(data), "got", n)
			return fs.ErrInvalid
		}
		i.lgr.Debug("File written to encrypted filesystem", "path", path)
		return nil
	}); err != nil {
		i.lgr.Error("Error walking source directory", "error", err)
		return err
	}

	if err := i.internalData.AddMount(config.MountConfig{
		Name:            i.name,
		MountPath:       i.destDir,
		SourceDir:       config.VFNode{Path: i.sourceDir, IsDir: true},
		EncryptionKeyID: i.name,
	}); err != nil {
		i.lgr.Error("Error adding mount to internal data", "error", err)
		return err
	}

	return nil
}
