package keychain

import (
	"crypto/rand"
	"fmt"

	"github.com/keybase/go-keychain"
)

func SetupKeychainAccess(svc string) error {
	// Generate a master encryption key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return err
	}

	// Store in keychain with specific access control
	item := keychain.NewItem()
	item.SetService(svc)
	item.SetAccount("root-key")
	item.SetData(masterKey)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	// This will prompt user for keychain access on first run
	return keychain.AddItem(item)
}

func RetrieveMasterKey(svc string) ([]byte, error) {
	query := keychain.NewItem()
	query.SetService(svc)
	query.SetAccount("root-key")
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("master key not found")
	}

	return results[0].Data, nil
}
