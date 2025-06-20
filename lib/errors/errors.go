package errors

import "fmt"

var ErrIsNotBootstrapped = fmt.Errorf("server is not bootstrapped, please run \"shimmer init\" first")
