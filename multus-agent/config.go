package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var (
	defaultHomeDir = AppDataDir("multus-agent", false)
)

type Host struct {
	Hostname   string
	BackupPath string
}

type config struct {
	StoragePath string
	BWLimit     string
	MaxSize     int64
	Login       string
	Hosts       []Host
}

func loadConfig() (*config, error) {
	configPath := filepath.Join(defaultHomeDir, "multus-agent.conf")
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	cfg := config{}
	if err = yaml.UnmarshalStrict(configFile, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.StoragePath) == 0 {
		return nil, fmt.Errorf("storagepath is not set")
	}
	if cfg.MaxSize == 0 {
		return nil, fmt.Errorf("maxsize is not set")
	}
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts configured")
	}
	if len(cfg.BWLimit) == 0 {
		return nil, fmt.Errorf("bwlimit not set")
	}
	if len(cfg.Login) == 0 {
		return nil, fmt.Errorf("login not set")
	}
	for _, host := range cfg.Hosts {
		if len(host.Hostname) == 0 {
			return nil, fmt.Errorf("missing hostname")
		}
		if len(host.BackupPath) == 0 {
			return nil, fmt.Errorf("missing backup path for %v", host.Hostname)
		}
	}
	return &cfg, nil
}
