package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
		fmt.Sprintf("%d", cfg.Timeout),
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
		stdOutPipe, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: StdoutPipe: %v\n", err)
			continue
		}
		stdErrPipe, err := cmd.StderrPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: StderrPipe: %v\n", err)
			continue
		}
		fmt.Printf("%s\n", cmd.String())
		err = cmd.Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Start: %v\n", err)
			return
		}
		go func() {
			var buf [1024]byte
			for {
				n, err := stdOutPipe.Read(buf[:])
				if n > 0 {
					os.Stdout.Write(buf[0:n])
					os.Stdout.Sync()
				}
				if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: stdout Read: %v\n", err)
					return
				}
			}
		}()
		go func() {
			var buf [1024]byte
			for {
				n, err := stdErrPipe.Read(buf[:])
				if n > 0 {
					os.Stderr.Write(buf[0:n])
					os.Stderr.Sync()
				}
				if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: stderr Read: %v\n", err)
					return
				}
			}
		}()

		if err = cmd.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Wait: %v\n", err)
		}
	}
	err = cleanup(ctx, cfg.StoragePath, cfg.MaxSize, cfg.DryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: %v\n", err)
	}
}
