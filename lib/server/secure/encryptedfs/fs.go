package encryptedfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// saltSize is the size of the salt used for key derivation
	saltSize = 32
	// nonceSize is the size of the nonce used for AES-GCM
	nonceSize = 12
	// keySize is the size of the AES key
	keySize = 32
	// encryptedFileSuffix is appended to encrypted file names
	encryptedFileSuffix = ".enc"
)

// EncryptedFS implements the billy.Filesystem interface with transparent encryption
type EncryptedFS struct {
	underlying billy.Filesystem
	cipher     cipher.AEAD
}

// New creates a new encrypted filesystem
// key: the encryption key (will be derived using PBKDF2)
// rootPath: the root directory where encrypted files will be stored
func New(key string, rootPath string) (*EncryptedFS, error) {
	// Create the underlying OS filesystem
	underlying := osfs.New(rootPath)

	// Derive a proper encryption key using PBKDF2
	salt := []byte("go-billy-encrypted-fs-salt-32bit") // Fixed salt for simplicity
	derivedKey := pbkdf2.Key([]byte(key), salt, 100000, keySize, sha256.New)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &EncryptedFS{
		underlying: underlying,
		cipher:     gcm,
	}, nil
}

// encryptedFileName returns the encrypted filename
func (fs *EncryptedFS) encryptedFileName(name string) string {
	if strings.HasSuffix(name, encryptedFileSuffix) {
		return name
	}
	return name + encryptedFileSuffix
}

// originalFileName returns the original filename from encrypted filename
func (fs *EncryptedFS) originalFileName(encName string) string {
	return strings.TrimSuffix(encName, encryptedFileSuffix)
}

// encrypt encrypts data using AES-GCM
func (fs *EncryptedFS) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, fs.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := fs.cipher.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (fs *EncryptedFS) decrypt(data []byte) ([]byte, error) {
	if len(data) < fs.cipher.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:fs.cipher.NonceSize()], data[fs.cipher.NonceSize():]
	plaintext, err := fs.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptedFile wraps a billy.File to provide transparent encryption/decryption
type encryptedFile struct {
	file      billy.File
	fs        *EncryptedFS
	name      string
	buffer    []byte
	position  int64
	isWriting bool
}

func (ef *encryptedFile) Name() string {
	return ef.name
}

func (ef *encryptedFile) Read(p []byte) (n int, err error) {
	if ef.buffer == nil {
		// Read and decrypt the entire file on first read
		data, err := io.ReadAll(ef.file)
		if err != nil {
			return 0, err
		}

		if len(data) == 0 {
			ef.buffer = []byte{}
		} else {
			ef.buffer, err = ef.fs.decrypt(data)
			if err != nil {
				return 0, err
			}
		}
	}

	// Read from buffer
	available := len(ef.buffer) - int(ef.position)
	if available <= 0 {
		return 0, io.EOF
	}

	if len(p) > available {
		n = available
	} else {
		n = len(p)
	}

	copy(p, ef.buffer[ef.position:ef.position+int64(n)])
	ef.position += int64(n)
	return n, nil
}

func (ef *encryptedFile) ReadAt(p []byte, off int64) (n int, err error) {
	if ef.buffer == nil {
		// Read and decrypt the entire file on first read
		data, err := io.ReadAll(ef.file)
		if err != nil {
			return 0, err
		}

		if len(data) == 0 {
			ef.buffer = []byte{}
		} else {
			ef.buffer, err = ef.fs.decrypt(data)
			if err != nil {
				return 0, err
			}
		}
	}

	if off < 0 || off >= int64(len(ef.buffer)) {
		return 0, io.EOF
	}

	if len(p) > len(ef.buffer)-int(off) {
		n = len(ef.buffer) - int(off)
	} else {
		n = len(p)
	}

	copy(p, ef.buffer[off:off+int64(n)])
	return n, nil
}

func (ef *encryptedFile) Write(p []byte) (n int, err error) {
	ef.isWriting = true
	if ef.buffer == nil {
		ef.buffer = make([]byte, 0)
	}

	// Extend buffer if necessary
	needed := int(ef.position) + len(p)
	if needed > len(ef.buffer) {
		newBuffer := make([]byte, needed)
		copy(newBuffer, ef.buffer)
		ef.buffer = newBuffer
	}

	// Write to buffer
	copy(ef.buffer[ef.position:], p)
	ef.position += int64(len(p))
	return len(p), nil
}

func (ef *encryptedFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		ef.position = offset
	case io.SeekCurrent:
		ef.position += offset
	case io.SeekEnd:
		if ef.buffer != nil {
			ef.position = int64(len(ef.buffer)) + offset
		} else {
			return 0, errors.New("cannot seek to end without reading file first")
		}
	}

	if ef.position < 0 {
		ef.position = 0
	}

	return ef.position, nil
}

func (ef *encryptedFile) Close() error {
	if ef.isWriting && ef.buffer != nil {
		// Encrypt and write the buffer to the underlying file
		encrypted, err := ef.fs.encrypt(ef.buffer[:ef.position])
		if err != nil {
			return err
		}

		// Truncate and write encrypted data
		if err := ef.file.Truncate(0); err != nil {
			return err
		}

		if _, err := ef.file.Seek(0, io.SeekStart); err != nil {
			return err
		}

		if _, err := ef.file.Write(encrypted); err != nil {
			return err
		}
	}

	return ef.file.Close()
}

func (ef *encryptedFile) Lock() error {
	return ef.file.Lock()
}

func (ef *encryptedFile) Unlock() error {
	return ef.file.Unlock()
}

func (ef *encryptedFile) WriteAt(p []byte, off int64) (n int, err error) {
	ef.isWriting = true
	if ef.buffer == nil {
		ef.buffer = make([]byte, 0)
	}

	// Extend buffer if necessary
	needed := int(off) + len(p)
	if needed > len(ef.buffer) {
		newBuffer := make([]byte, needed)
		copy(newBuffer, ef.buffer)
		ef.buffer = newBuffer
	}

	// Write to buffer
	copy(ef.buffer[off:], p)
	if off+int64(len(p)) > ef.position {
		ef.position = off + int64(len(p))
	}
	return len(p), nil
}

func (ef *encryptedFile) Truncate(size int64) error {
	if ef.buffer == nil {
		ef.buffer = make([]byte, 0)
	}

	if size < int64(len(ef.buffer)) {
		ef.buffer = ef.buffer[:size]
	} else {
		// Extend buffer with zeros
		newBuffer := make([]byte, size)
		copy(newBuffer, ef.buffer)
		ef.buffer = newBuffer
	}

	ef.isWriting = true
	return nil
}

// Filesystem interface implementation

func (fs *EncryptedFS) Create(filename string) (billy.File, error) {
	encName := fs.encryptedFileName(filename)
	file, err := fs.underlying.Create(encName)
	if err != nil {
		return nil, err
	}

	return &encryptedFile{
		file:      file,
		fs:        fs,
		name:      filename,
		position:  0,
		isWriting: true,
	}, nil
}

func (fs *EncryptedFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := fs.Create(filename)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func (fs *EncryptedFS) Open(filename string) (billy.File, error) {
	encName := fs.encryptedFileName(filename)
	file, err := fs.underlying.Open(encName)
	if err != nil {
		return nil, err
	}

	return &encryptedFile{
		file:     file,
		fs:       fs,
		name:     filename,
		position: 0,
	}, nil
}

func (fs *EncryptedFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	encName := fs.encryptedFileName(filename)
	file, err := fs.underlying.OpenFile(encName, flag, perm)
	if err != nil {
		return nil, err
	}

	return &encryptedFile{
		file:      file,
		fs:        fs,
		name:      filename,
		position:  0,
		isWriting: (flag&os.O_WRONLY != 0) || (flag&os.O_RDWR != 0),
	}, nil
}

func (fs *EncryptedFS) Stat(filename string) (os.FileInfo, error) {
	encName := fs.encryptedFileName(filename)
	info, err := fs.underlying.Stat(encName)
	if err != nil {
		return nil, err
	}

	// Return a wrapped FileInfo that shows the original filename
	return &encryptedFileInfo{
		info:         info,
		originalName: filename,
	}, nil
}

func (fs *EncryptedFS) Rename(oldpath, newpath string) error {
	oldEncName := fs.encryptedFileName(oldpath)
	newEncName := fs.encryptedFileName(newpath)
	return fs.underlying.Rename(oldEncName, newEncName)
}

func (fs *EncryptedFS) Remove(filename string) error {
	encName := fs.encryptedFileName(filename)
	return fs.underlying.Remove(encName)
}

func (fs *EncryptedFS) Join(elem ...string) string {
	return fs.underlying.Join(elem...)
}

func (fs *EncryptedFS) TempFile(dir, prefix string) (billy.File, error) {
	file, err := fs.underlying.TempFile(dir, prefix)
	if err != nil {
		return nil, err
	}

	return &encryptedFile{
		file:      file,
		fs:        fs,
		name:      file.Name(),
		position:  0,
		isWriting: true,
	}, nil
}

func (fs *EncryptedFS) ReadDir(path string) ([]os.FileInfo, error) {
	infos, err := fs.underlying.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var result []os.FileInfo
	for _, info := range infos {
		if strings.HasSuffix(info.Name(), encryptedFileSuffix) {
			originalName := fs.originalFileName(info.Name())
			result = append(result, &encryptedFileInfo{
				info:         info,
				originalName: originalName,
			})
		}
	}

	return result, nil
}

func (fs *EncryptedFS) MkdirAll(filename string, perm os.FileMode) error {
	return fs.underlying.MkdirAll(filename, perm)
}

// Symlink interface (if supported by underlying fs)
func (fs *EncryptedFS) Lstat(filename string) (os.FileInfo, error) {
	if symlinkFS, ok := fs.underlying.(billy.Symlink); ok {
		encName := fs.encryptedFileName(filename)
		info, err := symlinkFS.Lstat(encName)
		if err != nil {
			return nil, err
		}
		return &encryptedFileInfo{
			info:         info,
			originalName: filename,
		}, nil
	}
	return nil, billy.ErrNotSupported
}

func (fs *EncryptedFS) Symlink(target, link string) error {
	if symlinkFS, ok := fs.underlying.(billy.Symlink); ok {
		encTarget := fs.encryptedFileName(target)
		encLink := fs.encryptedFileName(link)
		return symlinkFS.Symlink(encTarget, encLink)
	}
	return billy.ErrNotSupported
}

func (fs *EncryptedFS) Readlink(link string) (string, error) {
	if symlinkFS, ok := fs.underlying.(billy.Symlink); ok {
		encLink := fs.encryptedFileName(link)
		target, err := symlinkFS.Readlink(encLink)
		if err != nil {
			return "", err
		}
		return fs.originalFileName(target), nil
	}
	return "", billy.ErrNotSupported
}

// Chroot interface (if supported by underlying fs)
func (fs *EncryptedFS) Chroot(path string) (billy.Filesystem, error) {
	if chrootFS, ok := fs.underlying.(billy.Chroot); ok {
		newUnderlying, err := chrootFS.Chroot(path)
		if err != nil {
			return nil, err
		}
		return &EncryptedFS{
			underlying: newUnderlying,
			cipher:     fs.cipher,
		}, nil
	}
	return nil, billy.ErrNotSupported
}

func (fs *EncryptedFS) Root() string {
	if chrootFS, ok := fs.underlying.(billy.Chroot); ok {
		return chrootFS.Root()
	}
	return "/"
}

// Capabilities interface
func (fs *EncryptedFS) Capabilities() billy.Capability {
	if capableFS, ok := fs.underlying.(billy.Capable); ok {
		return capableFS.Capabilities()
	}
	return billy.DefaultCapabilities
}

// encryptedFileInfo wraps os.FileInfo to show original filenames
type encryptedFileInfo struct {
	info         os.FileInfo
	originalName string
}

func (efi *encryptedFileInfo) Name() string       { return efi.originalName }
func (efi *encryptedFileInfo) Size() int64        { return efi.info.Size() }
func (efi *encryptedFileInfo) Mode() os.FileMode  { return efi.info.Mode() }
func (efi *encryptedFileInfo) ModTime() time.Time { return efi.info.ModTime() }
func (efi *encryptedFileInfo) IsDir() bool        { return efi.info.IsDir() }
func (efi *encryptedFileInfo) Sys() interface{}   { return efi.info.Sys() }

// Ensure our implementation satisfies the billy.Filesystem interface
var _ billy.Filesystem = (*EncryptedFS)(nil)
var _ billy.Symlink = (*EncryptedFS)(nil)
var _ billy.Chroot = (*EncryptedFS)(nil)
var _ billy.Capable = (*EncryptedFS)(nil)
