package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = os.MkdirAll(cfg.StoragePath, 0700)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defaultArgs := []string{
		"--timeout",
		"10",
		"--bwlimit",
		cfg.BWLimit,
		"-av",
		"-e",
		"ssh",
	}
	if len(cfg.Includes) == 0 && len(cfg.Excludes) == 0 {
		defaultArgs = append(defaultArgs, []string{
			"--include",
			"**.gz.enc",
			"--include",
			"sig.cache",
			"--exclude",
			"*",
		}...)
	} else {
		for _, inc := range cfg.Includes {
			defaultArgs = append(defaultArgs, []string{"--include", inc}...)
		}
		for _, exc := range cfg.Excludes {
			defaultArgs = append(defaultArgs, []string{"--exclude", exc}...)
		}
	}

	for _, host := range cfg.Hosts {
		fmt.Printf("syncing %s\n", host.Hostname)
		storagePath := filepath.Join(cfg.StoragePath, host.Hostname)
		err = os.MkdirAll(storagePath, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v -- skipping %v",
				err, host.Hostname)
			continue
		}
		backupPath := filepath.Clean(host.BackupPath)
		args := append(defaultArgs, []string{
			cfg.Login + "@" + host.Hostname + ":" + filepath.Join(backupPath) + string(os.PathSeparator),
			storagePath,
		}...)

		cmd := exec.CommandContext(ctx, "/usr/local/bin/rsync", args...)
		fmt.Printf("%s\n", cmd.String())
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		fmt.Printf("%s\n\n", stdoutStderr)
	}
	cancel()

	err = cleanup(cfg.StoragePath, cfg.MaxSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: %v\n", err)
	}
}
