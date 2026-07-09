//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// configureDetached puts the background child in its own session so it outlives
// the parent process.
func configureDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
