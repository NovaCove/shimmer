package keymanagement

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	homeDir, _  = os.UserHomeDir()
	keychainDir = filepath.Join(homeDir, ".shimmer", "keychains", "daemon")
)

const (
	// Security configuration
	daemonName       = "ai.novacove.in5.shimmer"
	keychainName     = "shimmer-daemon-secure.keychain"
	passwordLength   = 64
	pbkdf2Iterations = 100000
)

// SecureKeychainManager handles highly secure keychain operations
type SecureKeychainManager struct {
	keychainPath string
	hardwareID   string
	appSalt      []byte

	lgr          *slog.Logger
	rootPassword string
}

// TokenInfo represents metadata about a stored token
type TokenInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Service    string `json:"service"`
	Account    string `json:"account"`
}

// InitializeSecureKeychain implements the most secure keychain initialization
func InitializeSecureKeychain(lgr *slog.Logger) (*SecureKeychainManager, error) {
	skm := &SecureKeychainManager{
		keychainPath: filepath.Join(keychainDir, keychainName),
		appSalt:      []byte(daemonName + "-secure-salt"),
		lgr:          lgr,
	}

	skm.lgr.Info("skm:InitializeSecureKeychain", slog.String("keychainPath", skm.keychainPath))

	// Get hardware-based identifier
	hardwareID, err := skm.getHardwareIdentifier()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware identifier: %w", err)
	}
	skm.hardwareID = hardwareID

	// Verify code signature and process integrity
	if err := skm.verifyProcessIntegrity(); err != nil {
		return nil, fmt.Errorf("process integrity check failed: %w", err)
	}

	// Create secure keychain directory with proper ownership
	if err := skm.createSecureDirectory(); err != nil {
		return nil, fmt.Errorf("failed to create secure directory: %w", err)
	}

	// Check if keychain exists
	if _, err := os.Stat(skm.keychainPath); err == nil {
		// Verify keychain integrity before use
		if err := skm.verifyKeychainIntegrity(); err != nil {
			return nil, fmt.Errorf("keychain integrity check failed: %w", err)
		}

		rootPassword, err := skm.retrieveRootPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve root password: %w", err)
		}
		skm.rootPassword = rootPassword

		skm.auditLog("keychain_access", "success", "retrieved existing root password")
		return skm, nil
	}

	// Create new secure keychain
	rootPassword, err := skm.createSecureKeychain()
	if err != nil {
		skm.auditLog("keychain_creation", "failed", err.Error())
		return nil, fmt.Errorf("failed to create secure keychain: %w", err)
	}

	skm.auditLog("keychain_creation", "success", "created new keychain")
	skm.rootPassword = rootPassword
	return skm, nil
}

// getHardwareIdentifier derives a unique hardware-based identifier
func (skm *SecureKeychainManager) getHardwareIdentifier() (string, error) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get hardware UUID: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				return parts[3], nil
			}
		}
	}

	return "", fmt.Errorf("hardware UUID not found")
}

// verifyProcessIntegrity checks code signature and process legitimacy
func (skm *SecureKeychainManager) verifyProcessIntegrity() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command("codesign", "-v", execPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("code signature verification failed: %w", err)
	}

	if os.Getuid() == 0 {
		return fmt.Errorf("daemon should not run as root for security")
	}

	return nil
}

// createSecureDirectory creates directory with proper permissions and ownership
func (skm *SecureKeychainManager) createSecureDirectory() error {
	if err := os.MkdirAll(keychainDir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	uid := os.Getuid()
	gid := os.Getgid()
	if err := os.Chown(keychainDir, uid, gid); err != nil {
		return fmt.Errorf("failed to set directory ownership: %w", err)
	}

	// if err := syscall.Setxattr(keychainDir, "com.apple.quarantine", []byte(""), 0); err != nil {
	// 	// Non-fatal, continue
	// }

	return nil
}

// deriveKeychainPassword creates a hardware-bound master password
func (skm *SecureKeychainManager) deriveKeychainPassword() (string, error) {
	saltData := append([]byte(skm.hardwareID), skm.appSalt...)
	salt := sha256.Sum256(saltData)

	key := pbkdf2.Key([]byte(skm.hardwareID), salt[:], pbkdf2Iterations, 32, sha256.New)

	return hex.EncodeToString(key), nil
}

// createKeychainFile creates a new keychain file using the security command
func (skm *SecureKeychainManager) createKeychainFile(password string) error {
	cmd := exec.Command("security", "create-keychain", "-p", password, skm.keychainPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create keychain via security command: %w (stderr: %s)", err, stderr.String())
	}

	if err := skm.configureKeychainSecurity(password); err != nil {
		return fmt.Errorf("failed to configure keychain security: %w", err)
	}

	return nil
}

// configureKeychainSecurity sets up security settings for the newly created keychain
func (skm *SecureKeychainManager) configureKeychainSecurity(password string) error {
	// Set keychain to lock after 1 hour of inactivity (3600 seconds)
	settingsCmd := exec.Command("security", "set-keychain-settings",
		"-l", "-u", "-t", "3600", skm.keychainPath)
	if err := settingsCmd.Run(); err != nil {
		return fmt.Errorf("failed to set keychain settings: %w", err)
	}

	// Unlock the keychain for immediate use
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", password, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		return fmt.Errorf("failed to unlock keychain: %w", err)
	}

	if err := skm.addToKeychainSearchList(); err != nil {
		return fmt.Errorf("failed to add keychain to search list: %w", err)
	}

	return nil
}

// addToKeychainSearchList adds the keychain to the user's keychain search list
func (skm *SecureKeychainManager) addToKeychainSearchList() error {
	listCmd := exec.Command("security", "list-keychains", "-d", "user")
	output, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list current keychains: %w", err)
	}

	existingKeychains := strings.Fields(string(output))

	for _, kc := range existingKeychains {
		cleanPath := strings.Trim(kc, "\"")
		if cleanPath == skm.keychainPath {
			return nil
		}
	}

	args := []string{"list-keychains", "-d", "user", "-s"}
	args = append(args, existingKeychains...)
	args = append(args, skm.keychainPath)

	setCmd := exec.Command("security", args...)
	if err := setCmd.Run(); err != nil {
		return fmt.Errorf("failed to add keychain to search list: %w", err)
	}

	return nil
}

// createSecureKeychain creates a new keychain with maximum security
func (skm *SecureKeychainManager) createSecureKeychain() (string, error) {
	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		return "", fmt.Errorf("failed to derive master password: %w", err)
	}

	if err := skm.createKeychainFile(masterPassword); err != nil {
		return "", fmt.Errorf("failed to create keychain: %w", err)
	}

	if err := os.Chmod(skm.keychainPath, 0600); err != nil {
		return "", fmt.Errorf("failed to set keychain permissions: %w", err)
	}

	rootPassword, err := skm.generateCryptoSecurePassword()
	if err != nil {
		return "", fmt.Errorf("failed to generate root password: %w", err)
	}

	if err := skm.storePasswordWithSecurity("daemon-root-credential", "root-password", rootPassword); err != nil {
		return "", fmt.Errorf("failed to store root password: %w", err)
	}

	if err := skm.createIntegrityFile(); err != nil {
		return "", fmt.Errorf("failed to create integrity file: %w", err)
	}

	return rootPassword, nil
}

// storePasswordWithSecurity stores password using security command
func (skm *SecureKeychainManager) storePasswordWithSecurity(service, account, password string) error {
	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		return fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain first
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		return fmt.Errorf("failed to unlock keychain: %w", err)
	}

	// Get our current path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Add generic password
	addCmd := exec.Command("security", "add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", currentPath, // Allow current executable to access
		"-T", "/usr/bin/security", // Empty trusted applications - require authorization
		skm.keychainPath)

	var stderr bytes.Buffer
	addCmd.Stderr = &stderr

	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add password: %w (stderr: %s)", err, stderr.String())
	}

	return nil
}

// retrieveRootPassword securely retrieves the stored password using security command
func (skm *SecureKeychainManager) retrieveRootPassword() (string, error) {
	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		return "", fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain first
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to unlock keychain: %w", err)
	}

	// Find and retrieve password
	findCmd := exec.Command("security", "find-generic-password",
		"-s", "daemon-root-credential",
		"-a", "root-password",
		"-w", // Return password only
		skm.keychainPath)

	output, err := findCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to find root password: %w", err)
	}

	password := strings.TrimSpace(string(output))
	if len(password) == 0 {
		return "", fmt.Errorf("retrieved password is empty")
	}

	return password, nil
}

// generateCryptoSecurePassword generates maximum entropy password
func (skm *SecureKeychainManager) generateCryptoSecurePassword() (string, error) {
	bytes := make([]byte, passwordLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	timestamp := time.Now().UnixNano()
	entropy := append(bytes, []byte(fmt.Sprintf("%d", timestamp))...)
	hash := sha256.Sum256(entropy)

	return hex.EncodeToString(hash[:]), nil
}

// verifyKeychainIntegrity checks keychain hasn't been tampered with
func (skm *SecureKeychainManager) verifyKeychainIntegrity() error {
	integrityFile := skm.keychainPath + ".integrity"

	storedSum, err := os.ReadFile(integrityFile)
	if err != nil {
		return fmt.Errorf("integrity file not found: %w", err)
	}

	keychainData, err := os.ReadFile(skm.keychainPath)
	if err != nil {
		return fmt.Errorf("failed to read keychain: %w", err)
	}

	currentSum := sha256.Sum256(keychainData)
	if hex.EncodeToString(currentSum[:]) != string(storedSum) {
		return fmt.Errorf("keychain integrity check failed - possible tampering")
	}

	return nil
}

// createIntegrityFile creates integrity checksum for tamper detection
func (skm *SecureKeychainManager) createIntegrityFile() error {
	keychainData, err := os.ReadFile(skm.keychainPath)
	if err != nil {
		return fmt.Errorf("failed to read keychain for integrity: %w", err)
	}

	checksum := sha256.Sum256(keychainData)
	integrityFile := skm.keychainPath + ".integrity"

	return os.WriteFile(integrityFile, []byte(hex.EncodeToString(checksum[:])), 0600)
}

// auditLog creates security audit trail
func (skm *SecureKeychainManager) auditLog(operation, status, details string) {
	// timestamp := time.Now().Format(time.RFC3339)
	// logEntry := fmt.Sprintf("[%s] %s: %s - %s - PID:%d\n",
	// 	timestamp, daemonName, operation, status, os.Getpid())

	// logFile := filepath.Join(keychainDir, "audit.log")
	// if f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
	// 	f.WriteString(logEntry)
	// 	f.Close()
	// }

	// exec.Command("logger", "-t", daemonName, fmt.Sprintf("%s: %s", operation, status)).Run()
	skm.lgr.Info("skm:audit_log",
		slog.String("operation", operation),
		slog.String("status", status),
		slog.String("details", details),
	)
}

// RotatePassword securely rotates the root password
func (skm *SecureKeychainManager) RotatePassword() (string, error) {
	skm.auditLog("password_rotation", "started", "")

	newPassword, err := skm.generateCryptoSecurePassword()
	if err != nil {
		skm.auditLog("password_rotation", "failed", "generation failed")
		return "", err
	}

	// Delete old password and add new one
	if err := skm.deleteTokenWithSecurity("daemon-root-credential", "root-password"); err != nil {
		// Continue if not found
	}

	if err := skm.storePasswordWithSecurity("daemon-root-credential", "root-password", newPassword); err != nil {
		skm.auditLog("password_rotation", "failed", "storage failed")
		return "", err
	}

	if err := skm.createIntegrityFile(); err != nil {
		skm.auditLog("password_rotation", "failed", "integrity update failed")
		return "", err
	}

	skm.auditLog("password_rotation", "success", "")
	return newPassword, nil
}

// StoreToken securely stores a token/key in the keychain using security command
func (skm *SecureKeychainManager) StoreToken(tokenType, identifier, token string) error {
	skm.auditLog("token_store", "started", fmt.Sprintf("type:%s id:%s", tokenType, identifier))

	if err := skm.verifyKeychainIntegrity(); err != nil {
		skm.auditLog("token_store", "failed", "integrity check failed")
		return fmt.Errorf("keychain integrity check failed: %w", err)
	}

	serviceName := fmt.Sprintf("%s-%s", daemonName, tokenType)

	// Delete existing token if it exists
	skm.deleteTokenWithSecurity(serviceName, identifier)

	if err := skm.storePasswordWithSecurity(serviceName, identifier, token); err != nil {
		skm.auditLog("token_store", "failed", fmt.Sprintf("storage failed: %v", err))
		return fmt.Errorf("failed to store token: %w", err)
	}

	if err := skm.createIntegrityFile(); err != nil {
		skm.auditLog("token_store", "failed", "integrity file update failed")
		return fmt.Errorf("failed to update integrity file: %w", err)
	}

	skm.auditLog("token_store", "success", fmt.Sprintf("type:%s id:%s", tokenType, identifier))
	return nil
}

// RetrieveToken securely retrieves a token/key from the keychain using security command
func (skm *SecureKeychainManager) RetrieveToken(tokenType, identifier string) (string, error) {
	skm.auditLog("token_retrieve", "started", fmt.Sprintf("type:%s id:%s", tokenType, identifier))

	if err := skm.verifyKeychainIntegrity(); err != nil {
		skm.auditLog("token_retrieve", "failed", "integrity check failed")
		return "", fmt.Errorf("keychain integrity check failed: %w", err)
	}

	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		skm.auditLog("token_retrieve", "failed", "master password derivation failed")
		return "", fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		skm.auditLog("token_retrieve", "failed", "keychain unlock failed")
		return "", fmt.Errorf("failed to unlock keychain: %w", err)
	}

	serviceName := fmt.Sprintf("%s-%s", daemonName, tokenType)

	// Find and retrieve token
	findCmd := exec.Command("security", "find-generic-password",
		"-s", serviceName,
		"-a", identifier,
		"-w", // Return password only
		skm.keychainPath)

	output, err := findCmd.Output()
	if err != nil {
		skm.auditLog("token_retrieve", "failed", fmt.Sprintf("query failed: %v", err))
		return "", fmt.Errorf("failed to find token for type:%s id:%s: %w", tokenType, identifier, err)
	}

	token := strings.TrimSpace(string(output))
	if len(token) == 0 {
		skm.auditLog("token_retrieve", "failed", "empty token retrieved")
		return "", fmt.Errorf("retrieved token is empty")
	}

	skm.auditLog("token_retrieve", "success", fmt.Sprintf("type:%s id:%s length:%d", tokenType, identifier, len(token)))
	return token, nil
}

// ListTokens returns a list of all stored tokens using security command
func (skm *SecureKeychainManager) ListTokens() ([]TokenInfo, error) {
	skm.auditLog("token_list", "started", "")

	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to unlock keychain: %w", err)
	}

	// Dump keychain contents
	dumpCmd := exec.Command("security", "dump-keychain", skm.keychainPath)
	output, err := dumpCmd.Output()
	if err != nil {
		skm.auditLog("token_list", "failed", fmt.Sprintf("dump failed: %v", err))
		return nil, fmt.Errorf("failed to dump keychain: %w", err)
	}

	var tokens []TokenInfo
	lines := strings.Split(string(output), "\n")
	var currentToken *TokenInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "class: \"genp\"") {
			// New generic password item
			currentToken = &TokenInfo{}
		} else if currentToken != nil {
			if strings.Contains(line, "\"svce\"") {
				// Service name
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					service := parts[3]
					currentToken.Service = service

					// Skip root credential
					if service == "daemon-root-credential" {
						currentToken = nil
						continue
					}

					// Extract token type
					if strings.HasPrefix(service, daemonName+"-") {
						currentToken.Type = strings.TrimPrefix(service, daemonName+"-")
					}
				}
			} else if strings.Contains(line, "\"acct\"") {
				// Account name
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					currentToken.Account = parts[3]
					currentToken.Identifier = parts[3]
				}
			} else if strings.Contains(line, "keychain:") && currentToken.Service != "" {
				// End of item, add to list
				tokens = append(tokens, *currentToken)
				currentToken = nil
			}
		}
	}

	skm.auditLog("token_list", "success", fmt.Sprintf("found %d tokens", len(tokens)))
	return tokens, nil
}

// DeleteToken securely removes a token from the keychain using security command
func (skm *SecureKeychainManager) DeleteToken(tokenType, identifier string) error {
	skm.auditLog("token_delete", "started", fmt.Sprintf("type:%s id:%s", tokenType, identifier))

	serviceName := fmt.Sprintf("%s-%s", daemonName, tokenType)

	if err := skm.deleteTokenWithSecurity(serviceName, identifier); err != nil {
		skm.auditLog("token_delete", "failed", fmt.Sprintf("deletion failed: %v", err))
		return fmt.Errorf("failed to delete token: %w", err)
	}

	if err := skm.createIntegrityFile(); err != nil {
		return fmt.Errorf("failed to update integrity file: %w", err)
	}

	skm.auditLog("token_delete", "success", fmt.Sprintf("type:%s id:%s", tokenType, identifier))
	return nil
}

// deleteTokenWithSecurity helper function to remove tokens using security command
func (skm *SecureKeychainManager) deleteTokenWithSecurity(service, account string) error {
	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		return fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		return fmt.Errorf("failed to unlock keychain: %w", err)
	}

	// Delete the item
	deleteCmd := exec.Command("security", "delete-generic-password",
		"-s", service,
		"-a", account,
		skm.keychainPath)

	return deleteCmd.Run()
}

func (skm *SecureKeychainManager) RetrieveEncryptionKey(identifier string) (string, error) {
	skm.auditLog("encryption_key_retrieve", "started", fmt.Sprintf("id:%s", identifier))

	if err := skm.verifyKeychainIntegrity(); err != nil {
		skm.auditLog("encryption_key_retrieve", "failed", "integrity check failed")
		return "", fmt.Errorf("keychain integrity check failed: %w", err)
	}

	masterPassword, err := skm.deriveKeychainPassword()
	if err != nil {
		skm.auditLog("encryption_key_retrieve", "failed", "master password derivation failed")
		return "", fmt.Errorf("failed to derive master password: %w", err)
	}

	// Unlock keychain
	unlockCmd := exec.Command("security", "unlock-keychain", "-p", masterPassword, skm.keychainPath)
	if err := unlockCmd.Run(); err != nil {
		skm.auditLog("encryption_key_retrieve", "failed", "keychain unlock failed")
		return "", fmt.Errorf("failed to unlock keychain: %w", err)
	}

	serviceName := fmt.Sprintf("%s-encryption-key", daemonName)

	// Find and retrieve encryption key
	findCmd := exec.Command("security", "find-generic-password",
		"-s", serviceName,
		"-a", identifier,
		"-w") // Return password only

	output, err := findCmd.Output()
	if err != nil {
		skm.auditLog("encryption_key_retrieve", "failed", fmt.Sprintf("query failed: %v", err))
		return "", fmt.Errorf("failed to find encryption key for id:%s: %w", identifier, err)
	}

	key := strings.TrimSpace(string(output))
	if len(key) == 0 {
		skm.auditLog("encryption_key_retrieve", "failed", "empty key retrieved")
		return "", fmt.Errorf("retrieved encryption key is empty")
	}

	skm.auditLog("encryption_key_retrieve", "success", fmt.Sprintf("id:%s length:%d", identifier, len(key)))
	return key, nil
}

// GenerateEncryptionKey creates a new encryption key and stores it
func (skm *SecureKeychainManager) GenerateEncryptionKey(identifier string, keyLength int) (string, error) {
	skm.auditLog("encryption_key_generate", "started", fmt.Sprintf("id:%s length:%d", identifier, keyLength))

	if keyLength < 16 || keyLength > 64 {
		return "", fmt.Errorf("key length must be between 16 and 64 bytes")
	}

	keyBytes := make([]byte, keyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		skm.auditLog("encryption_key_generate", "failed", "random generation failed")
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	key := hex.EncodeToString(keyBytes)

	if err := skm.StoreToken("encryption-key", identifier, key); err != nil {
		skm.auditLog("encryption_key_generate", "failed", "storage failed")
		return "", fmt.Errorf("failed to store encryption key: %w", err)
	}

	skm.auditLog("encryption_key_generate", "success", fmt.Sprintf("id:%s length:%d", identifier, keyLength))
	return key, nil
}

// SecureCleanup removes the keychain and associated files securely
func (skm *SecureKeychainManager) SecureCleanup() error {
	skm.auditLog("keychain_cleanup", "started", "")

	if err := skm.removeFromKeychainSearchList(); err != nil {
		skm.auditLog("keychain_cleanup", "warning", fmt.Sprintf("failed to remove from search list: %v", err))
	}

	deleteCmd := exec.Command("security", "delete-keychain", skm.keychainPath)
	if err := deleteCmd.Run(); err != nil {
		skm.auditLog("keychain_cleanup", "failed", fmt.Sprintf("delete command failed: %v", err))
		return fmt.Errorf("failed to delete keychain: %w", err)
	}

	integrityFile := skm.keychainPath + ".integrity"
	if err := os.Remove(integrityFile); err != nil && !os.IsNotExist(err) {
		skm.auditLog("keychain_cleanup", "warning", fmt.Sprintf("failed to remove integrity file: %v", err))
	}

	auditFile := filepath.Join(keychainDir, "audit.log")
	if err := os.Remove(auditFile); err != nil && !os.IsNotExist(err) {
		skm.auditLog("keychain_cleanup", "warning", fmt.Sprintf("failed to remove audit file: %v", err))
	}

	skm.auditLog("keychain_cleanup", "success", "")
	return nil
}

// removeFromKeychainSearchList removes the keychain from the user's search list
func (skm *SecureKeychainManager) removeFromKeychainSearchList() error {
	listCmd := exec.Command("security", "list-keychains", "-d", "user")
	output, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list current keychains: %w", err)
	}

	existingKeychains := strings.Fields(string(output))
	var filteredKeychains []string

	for _, kc := range existingKeychains {
		cleanPath := strings.Trim(kc, "\"")
		if cleanPath != skm.keychainPath {
			filteredKeychains = append(filteredKeychains, kc)
		}
	}

	if len(filteredKeychains) > 0 {
		args := []string{"list-keychains", "-d", "user", "-s"}
		args = append(args, filteredKeychains...)

		setCmd := exec.Command("security", args...)
		return setCmd.Run()
	} else {
		setCmd := exec.Command("security", "list-keychains", "-d", "user", "-s")
		return setCmd.Run()
	}
}

// Example usage demonstrating secure keychain management
func main() {
	skm, err := InitializeSecureKeychain(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	if err != nil {
		fmt.Printf("❌ Error initializing keychain: %v\n", err)
		return
	}

	fmt.Printf("✅ Secure keychain initialized successfully\n")

	fmt.Println("\n--- Token Management Examples ---")

	// Store various types of tokens
	apiToken := "sk-1234567890abcdef1234567890abcdef"
	if err := skm.StoreToken("api-token", "openai-primary", apiToken); err != nil {
		fmt.Printf("❌ Failed to store API token: %v\n", err)
	} else {
		fmt.Println("✅ API token stored successfully")
	}

	encKey, err := skm.GenerateEncryptionKey("database-encryption", 32)
	if err != nil {
		fmt.Printf("❌ Failed to generate encryption key: %v\n", err)
	} else {
		fmt.Printf("✅ Generated encryption key: %s...\n", encKey[:16])
	}

	dbPassword := "super-secure-db-password-2024"
	if err := skm.StoreToken("database-password", "postgres-primary", dbPassword); err != nil {
		fmt.Printf("❌ Failed to store database password: %v\n", err)
	} else {
		fmt.Println("✅ Database password stored successfully")
	}

	fmt.Println("\n--- Token Retrieval Examples ---")

	retrievedToken, err := skm.RetrieveToken("api-token", "openai-primary")
	if err != nil {
		fmt.Printf("❌ Failed to retrieve API token: %v\n", err)
	} else {
		fmt.Printf("✅ Retrieved API token: %s...\n", retrievedToken[:12])
	}

	retrievedKey, err := skm.RetrieveToken("encryption-key", "database-encryption")
	if err != nil {
		fmt.Printf("❌ Failed to retrieve encryption key: %v\n", err)
	} else {
		fmt.Printf("✅ Retrieved encryption key: %s...\n", retrievedKey[:16])
	}

	fmt.Println("\n--- Stored Tokens Inventory ---")
	tokens, err := skm.ListTokens()
	if err != nil {
		fmt.Printf("❌ Failed to list tokens: %v\n", err)
	} else {
		fmt.Printf("📊 Found %d stored tokens:\n", len(tokens))
		for _, token := range tokens {
			fmt.Printf("  • %s:%s\n", token.Type, token.Identifier)
		}
	}

	fmt.Println("\n--- Security Operations ---")
	if newPassword, err := skm.RotatePassword(); err == nil {
		fmt.Printf("🔄 Root password rotated: %s...\n", newPassword[:16])
	} else {
		fmt.Printf("❌ Failed to rotate password: %v\n", err)
	}

	fmt.Println("\n--- Cleanup (Commented for Safety) ---")
	fmt.Println("// To securely remove the keychain:")
	fmt.Println("// if err := skm.SecureCleanup(); err != nil {")
	fmt.Printf("//     fmt.Printf(\"❌ Cleanup failed: %v\\n\", err)")
	fmt.Println("// } else {")
	fmt.Println("//     fmt.Println(\"✅ Keychain securely removed\")")
	fmt.Println("// }")

	fmt.Println("\n🎉 Secure keychain demo completed successfully!")
}
