//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// Windows process creation flags for a fully detached background child.
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
)

// configureDetached makes cmd run as a detached, window-less background process
// that outlives the parent (no console flash, its own process group).
func configureDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcessGroup,
	}
}
