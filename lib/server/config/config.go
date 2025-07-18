package config

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
)

type FileConfig struct {
	UnixSocket       string      `json:"unix_socket"`
	KeychainPrefix   string      `json:"keychain_prefix"`
	SharedSecretName string      `json:"shared_secret_name"`
	AuditConfig      AuditConfig `json:"audit_config"`
}

type AuditConfig struct {
	Enabled     bool   `json:"enabled"`
	Destination string `json:"destination"` // e.g., "file://~/.shimmer/audit.log"
}

type VFNode struct {
	Path       string   `json:"path"`
	IsDir      bool     `json:"is_dir"`
	Children   []VFNode `json:"children,omitempty"`
	ContentRef string   `json:"content_ref,omitempty"`
}

type MountConfig struct {
	Name            string `json:"name"`
	MountPath       string `json:"mount_path"`
	SourceDir       VFNode `json:"source_dir"`
	EncryptionKeyID string `json:"encryption_key_id"`
}

type MountSingleConfig struct {
	MountConfig
	SourceFile  string `json:"source_file"`
	Destination string `json:"destination"` // must be absolute path
}

type DataConfig struct {
	Mounts      []MountConfig       `json:"mounts"`
	SingleFiles []MountSingleConfig `json:"single_files"`
}

type ConfigLoader interface {
	LoadConfig(path string) (*FileConfig, error)
}

var ErrInvalidConfig = errors.New("invalid configuration file")

type fsConfigLoader struct {
	fs fs.FS
}

func NewFSConfigLoader(fsys fs.FS) ConfigLoader {
	return &fsConfigLoader{fs: fsys}
}

func (fcl *fsConfigLoader) LoadConfig(path string) (*FileConfig, error) {
	f, err := fcl.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var config FileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, ErrInvalidConfig
	}
	return &config, nil
}
