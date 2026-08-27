//go:build !windows

package backend

import "os"

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
