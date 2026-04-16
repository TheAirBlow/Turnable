package common

import (
	"fmt"
)

// WrapError prepends an additional error message to an error
func WrapError(message string, err error) error {
	return fmt.Errorf("%s: %w", message, err)
}

// JoinErr combines two errors into a single multi-error, returning whichever is non-nil
func JoinErr(base error, next error) error {
	if base == nil {
		return next
	}
	if next == nil {
		return base
	}
	return fmt.Errorf("%w; %w", base, next)
}
