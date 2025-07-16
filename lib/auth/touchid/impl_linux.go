package touchid

import "errors"

func Authenticate(reason string) (bool, error) {
	return false, errors.New("TouchID is not supported on Windows")
}
