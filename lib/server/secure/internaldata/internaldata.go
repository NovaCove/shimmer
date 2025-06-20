package internaldata

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/NovaCove/shimmer/lib/server/config"
	"github.com/NovaCove/shimmer/lib/server/secure/encryptedfs"
	"github.com/NovaCove/shimmer/lib/server/secure/keymanagement"
	"github.com/dgraph-io/badger/v4"
	"github.com/go-git/go-billy/v5"
)

type InternalData interface {
	Load() error
	LoadMounts() (*config.DataConfig, error)

	DecryptMount(mount *config.MountConfig) (billy.Filesystem, error)

	NumMounts() int
	Bootstrap() error
}

type internalData struct {
	dataPath      string
	encryptionKey []byte
	db            *badger.DB

	mounts *config.DataConfig

	lgr *slog.Logger
	skm *keymanagement.SecureKeychainManager
}

func NewInternalData(dataPath string, encryptionKey []byte, lgr *slog.Logger, skm *keymanagement.SecureKeychainManager) InternalData {
	return &internalData{
		dataPath:      dataPath,
		encryptionKey: encryptionKey,

		lgr: lgr,
		skm: skm,
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
	opts := badger.DefaultOptions("").
		WithIndexCacheSize(100 * 1024 * 1024). // 100 MB
		WithEncryptionKey(id.encryptionKey)

	var err error
	if id.db, err = badger.Open(opts); err != nil {
		return err
	}

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
		return nil, err
	}

	id.mounts = &mounts

	return &mounts, nil
}

func (id *internalData) DecryptMount(mount *config.MountConfig) (billy.Filesystem, error) {
	// Get key from the mount config
	keyID := mount.EncryptionKeyID
	if keyID == "" {
		return nil, errors.New("mount config does not specify an encryption key ID")
	}

	// Load the key from the keychain
	key, err := id.skm.RetrieveToken("password", keyID)
	if err != nil {
		return nil, err
	}

	// Decrypt the mount data
	fs, err := encryptedfs.New(key, mount.MountPath)
	if err != nil {
		return nil, err
	}

	return fs, nil
}

func (id *internalData) NumMounts() int {
	return len(id.mounts.Mounts) + len(id.mounts.SingleFiles)
}
