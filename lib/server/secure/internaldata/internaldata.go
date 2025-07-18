package internaldata

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/NovaCove/grainfs"
	"github.com/NovaCove/shimmer/lib/logger"
	"github.com/NovaCove/shimmer/lib/server/config"
	"github.com/NovaCove/shimmer/lib/server/secure/keymanagement"
	"github.com/dgraph-io/badger/v4"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
)

type InternalData interface {
	Load() error
	LoadMounts() (*config.DataConfig, error)

	DecryptMount(mount *config.MountConfig) (billy.Filesystem, error)

	NumMounts() int
	Bootstrap() error

	AddMount(mount config.MountConfig) error
	AddSingleFileMount(mount config.MountSingleConfig) error
	SaveMounts() error

	RetrieveMountByName(name string) (billy.Filesystem, error)
	DeleteMountByName(name string) error
	InvalidateMount(name string) error
	EjectKnownMount(name string) error
}

type internalData struct {
	dataPath      string
	encryptionKey []byte
	db            *badger.DB

	mounts *config.DataConfig

	isLoaded     bool
	isLoadedLock *sync.RWMutex

	lgr *slog.Logger
	skm *keymanagement.SecureKeychainManager
}

func NewInternalData(dataPath string, encryptionKey []byte, lgr *slog.Logger, skm *keymanagement.SecureKeychainManager) InternalData {
	return &internalData{
		dataPath:      dataPath,
		encryptionKey: encryptionKey,

		lgr: lgr,
		skm: skm,

		isLoadedLock: new(sync.RWMutex),
	}
}

func (id *internalData) ensureDataDir() error {
	if id.dataPath == "" {
		return errors.New("data path is not set")
	}

	// Create the data directory if it doesn't exist
	if err := os.MkdirAll(id.dataPath, 0755); err != nil {
		return err
	}
	return nil
}

func (id *internalData) Bootstrap() error {
	// Ensure the data directory exists
	if err := id.ensureDataDir(); err != nil {
		return err
	}

	// Load the Badger database
	if err := id.Load(); err != nil {
		return err
	}

	// Add a init document as a sort of health check.
	if err := id.db.Update(func(txn *badger.Txn) error {
		initData, err := json.Marshal(map[string]any{
			"version":       "unversioned",
			"initializedAt": time.Now().Format(time.RFC3339),
		})
		if err != nil {
			return err
		} else if err := txn.Set([]byte("init"), initData); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (id *internalData) Load() error {
	id.lgr.Debug("Loading internal data", "dataPath", id.dataPath)
	opts := badger.DefaultOptions("").
		WithIndexCacheSize(100 * 1024 * 1024). // 100 MB
		WithEncryptionKey(id.encryptionKey[0:32]).
		WithDir(id.dataPath).
		WithValueDir(id.dataPath).
		WithLogger(logger.AdaptLoggerToBadgerLogger(id.lgr))

	var err error
	if id.db, err = badger.Open(opts); err != nil {
		id.lgr.Error("Failed to open Badger database", "error", err)
		return err
	}

	id.isLoadedLock.Lock()
	id.isLoaded = true
	id.isLoadedLock.Unlock()

	return nil
}

func (id *internalData) LoadMounts() (*config.DataConfig, error) {
	var mounts config.DataConfig

	err := id.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("mounts"))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			if err := json.NewDecoder(bytes.NewReader(val)).Decode(&mounts); err != nil {
				return err
			}
			return nil
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			id.lgr.Debug("No mounts found in database, returning empty mounts config")
			return &mounts, nil
		}
		return nil, err
	}
	id.lgr.Debug("Loaded mounts from database", "mounts", mounts)

	id.mounts = &mounts

	return &mounts, nil
}

func (id *internalData) isMountsLoaded() bool {
	id.isLoadedLock.RLock()
	defer id.isLoadedLock.RUnlock()
	if !id.isLoaded {
		return false
	}

	if id.mounts == nil {
		id.mounts = &config.DataConfig{
			Mounts:      []config.MountConfig{},
			SingleFiles: []config.MountSingleConfig{},
		}
	}
	return true
}

func (id *internalData) SaveMounts() error {
	if !id.isMountsLoaded() {
		return errors.New("mounts are not loaded")
	}

	data, err := json.Marshal(id.mounts)
	if err != nil {
		return err
	}

	return id.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("mounts"), data)
	})
}

func (id *internalData) AddMount(mount config.MountConfig) error {
	if !id.isMountsLoaded() {
		return errors.New("mounts are not loaded")
	}

	// Add the mount to the mounts config
	id.mounts.Mounts = append(id.mounts.Mounts, mount)

	// Save the updated mounts config
	return id.SaveMounts()
}

func (id *internalData) AddSingleFileMount(mount config.MountSingleConfig) error {
	if !id.isMountsLoaded() {
		return errors.New("mounts are not loaded")
	}

	// Add the single file mount to the mounts config
	id.mounts.SingleFiles = append(id.mounts.SingleFiles, mount)

	// Save the updated mounts config
	return id.SaveMounts()
}

func (id *internalData) DecryptMount(mount *config.MountConfig) (billy.Filesystem, error) {
	// Get key from the mount config
	keyID := mount.EncryptionKeyID
	if keyID == "" {
		return nil, errors.New("mount config does not specify an encryption key ID")
	}

	// Load the key from the keychain
	key, err := id.skm.RetrieveEncryptionKey(keyID)
	if err != nil {
		return nil, err
	}

	// Decrypt the mount data
	id.lgr.Debug("Decrypting mount", "name", mount.Name, "sourceDir", mount.SourceDir.Path, "keyID", key, "mountPath", mount.MountPath)
	fs, err := grainfs.New(
		osfs.New(mount.MountPath),
		key,
	)
	if err != nil {
		return nil, err
	}

	return fs, nil
}

func (id *internalData) NumMounts() int {
	return len(id.mounts.Mounts) + len(id.mounts.SingleFiles)
}

var ErrMountNotFound = errors.New("mount not found")

func (id *internalData) RetrieveMountByName(name string) (billy.Filesystem, error) {
	if id.mounts == nil {
		return nil, errors.New("mounts are not loaded")
	}

	for _, mount := range id.mounts.Mounts {
		if mount.Name == name {
			return id.DecryptMount(&mount)
		}
	}

	for _, singleFile := range id.mounts.SingleFiles {
		if singleFile.Name == name {
			return id.DecryptMount(&singleFile.MountConfig)
		}
	}

	return nil, ErrMountNotFound
}

func (id *internalData) getMountConfigByName(name string) (*config.MountConfig, error) {
	if id.mounts == nil {
		return nil, errors.New("mounts are not loaded")
	}

	for _, mount := range id.mounts.Mounts {
		if mount.Name == name {
			return &mount, nil
		}
	}

	for _, singleFile := range id.mounts.SingleFiles {
		if singleFile.Name == name {
			return &singleFile.MountConfig, nil
		}
	}

	return nil, ErrMountNotFound
}

func (id *internalData) DeleteMountByName(name string) error {
	if id.mounts == nil {
		return errors.New("mounts are not loaded")
	}

	mntCfg, err := id.getMountConfigByName(name)
	if err != nil {
		return err
	}

	// Remove the mount from the filesystem
	if err := os.RemoveAll(mntCfg.MountPath); err != nil {
		id.lgr.Error("Failed to remove mount source directory", "name", name, "error", err)
		return err
	}

	for i, mount := range id.mounts.Mounts {
		if mount.Name == name {
			id.mounts.Mounts = append(id.mounts.Mounts[:i], id.mounts.Mounts[i+1:]...)
			return id.SaveMounts()
		}
	}

	for i, singleFile := range id.mounts.SingleFiles {
		if singleFile.Name == name {
			id.mounts.SingleFiles = append(id.mounts.SingleFiles[:i], id.mounts.SingleFiles[i+1:]...)
			return id.SaveMounts()
		}
	}

	return ErrMountNotFound
}

type FSSafeBillyFS struct {
	billy.Filesystem
}

func (fs *FSSafeBillyFS) Open(name string) (fs.File, error) {
	f, err := fs.Filesystem.Open(name)
	if err != nil {
		return nil, err
	}
	return FSSafeFile{
		File: f,
		fs:   fs.Filesystem,
	}, nil
}

type FSSafeFile struct {
	billy.File
	fs billy.Filesystem
}

func (f FSSafeFile) Stat() (fs.FileInfo, error) {
	// Ensure that the file is not nil before calling Stat
	if f.File == nil {
		return nil, errors.New("file is nil")
	}
	return f.fs.Stat(f.Name())
}

func (id *internalData) InvalidateMount(name string) error {
	if id.mounts == nil {
		return errors.New("mounts are not loaded")
	}

	for i, mount := range id.mounts.Mounts {
		if mount.Name == name {
			id.mounts.Mounts = append(id.mounts.Mounts[:i], id.mounts.Mounts[i+1:]...)
			return id.SaveMounts()
		}
	}

	for i, singleFile := range id.mounts.SingleFiles {
		if singleFile.Name == name {
			id.mounts.SingleFiles = append(id.mounts.SingleFiles[:i], id.mounts.SingleFiles[i+1:]...)
			return id.SaveMounts()
		}
	}

	return ErrMountNotFound
}

func (id *internalData) EjectKnownMount(name string) error {
	if id.mounts == nil {
		return errors.New("mounts are not loaded")
	}

	var conf *config.MountConfig
	for i, mount := range id.mounts.Mounts {
		if mount.Name == name {
			conf = &mount
			id.mounts.Mounts = append(id.mounts.Mounts[:i], id.mounts.Mounts[i+1:]...)
			break
		}
	}

	for i, singleFile := range id.mounts.SingleFiles {
		if singleFile.Name == name {
			conf = &singleFile.MountConfig
			id.mounts.SingleFiles = append(id.mounts.SingleFiles[:i], id.mounts.SingleFiles[i+1:]...)
			break
		}
	}

	if conf == nil {
		id.lgr.Error("Mount configuration not found for ejection", "name", name)
		return ErrMountNotFound
	}

	efs, err := id.DecryptMount(conf)
	if err != nil {
		id.lgr.Error("Failed to decrypt mount for ejection", "name", name, "error", err)
		return err
	}
	if efs == nil {
		id.lgr.Error("Failed to retrieve mount filesystem for ejection", "name", name)
		return ErrMountNotFound
	}

	ofs := osfs.New(conf.SourceDir.Path)

	// Walk the encrypted filesystem, replacing every unencrypted file back to the original source
	// directory.
	sfs := &FSSafeBillyFS{efs}
	err = util.Walk(efs, "/", func(path string, d os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			id.lgr.Debug("Removing directory", "path", path)
			if err := ofs.MkdirAll(path, d.Mode()); err != nil {
				id.lgr.Error("Failed to create directory in source", "path", path, "error", err)
				return err
			}
			return nil
		}

		contents, err := fs.ReadFile(sfs, path)
		if err != nil {
			id.lgr.Error("Failed to read file from encrypted filesystem", "path", path, "error", err)
			return err
		}

		f, err := ofs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, d.Mode())
		if err != nil {
			id.lgr.Error("Failed to create file in source directory", "path", path, "error", err)
			return err
		}
		defer f.Close()
		if _, err := f.Write(contents); err != nil {
			id.lgr.Error("Failed to write file to source directory", "path", path, "error", err)
			return err
		}

		id.lgr.Debug("File written to source directory", "path", path)
		return nil
	})

	if err != nil {
		id.lgr.Error("Failed to walk encrypted filesystem for ejection", "name", name, "error", err)
		return err
	}

	// Remove the encrypted filesystem directory
	if err := os.RemoveAll(conf.MountPath); err != nil {
		id.lgr.Error("Failed to remove encrypted filesystem directory", "mountPath", conf.MountPath, "error", err)
		return err
	}

	if err := id.SaveMounts(); err != nil {
		id.lgr.Error("Failed to save mounts during ejecting", "name", name, "error", err)
		return err
	}

	return nil
}
