//go:build windows

package backend

import "golang.org/x/sys/windows"

func replaceFile(from, to string) error {
	return windows.Rename(from, to)
}
