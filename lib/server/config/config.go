package config

type FileConfig struct {
	UnixSocket       string `json:"unix_socket"`
	KeychainPrefix   string `json:"keychain_prefix"`
	SharedSecretName string `json:"shared_secret_name"`
}

type VFNode struct {
	Path       string   `json:"path"`
	IsDir      bool     `json:"is_dir"`
	Children   []VFNode `json:"children,omitempty"`
	ContentRef string   `json:"content_ref,omitempty"`
}

type MountConfig struct {
	MountPath string `json:"mount_path"`
	RootNode  VFNode `json:"root_node"`
}

type DataConfig struct {
	Mounts []MountConfig `json:"mounts"`
}
