package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type SecureDaemon struct {
	masterKey []byte
	gcm       cipher.AEAD
	dataDir   string
}

func NewSecureDaemon() (*SecureDaemon, error) {
	// Retrieve master key from keychain
	masterKey, err := retrieveMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve master key: %w", err)
	}

	// Setup AES-GCM encryption
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create data directory
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".securedaemon")
	os.MkdirAll(dataDir, 0700)

	return &SecureDaemon{
		masterKey: masterKey,
		gcm:       gcm,
		dataDir:   dataDir,
	}, nil
}

func (d *SecureDaemon) encryptData(data []byte) ([]byte, error) {
	nonce := make([]byte, d.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := d.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (d *SecureDaemon) decryptData(ciphertext []byte) ([]byte, error) {
	nonceSize := d.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return d.gcm.Open(nil, nonce, ciphertext, nil)
}

func (d *SecureDaemon) storeSecureData(key string, data []byte) error {
	encrypted, err := d.encryptData(data)
	if err != nil {
		return err
	}

	filePath := filepath.Join(d.dataDir, key+".enc")
	return os.WriteFile(filePath, encrypted, 0600)
}

func (d *SecureDaemon) retrieveSecureData(key string) ([]byte, error) {
	filePath := filepath.Join(d.dataDir, key+".enc")
	encrypted, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return d.decryptData(encrypted)
}
