package touchid

import "errors"

func AuthenticateTouch(reason string) (bool, error) {
	return false, errors.New("TouchID is not supported on Windows")
}
