package main

import (
	"compress/gzip"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v2"
)

var (
	defaultHomeDir = AppDataDir("multus", false)
)

type BackupConfig struct {
	Group        string
	MaxIntervals uint16
	GZLevel      int
	PubkeyFile   string
	Paths        []string
	Excludes     []string
	rExcludes    []*regexp.Regexp
}

type RestoreConfig struct {
	SecretFile string
}

type config struct {
	Profile    bool
	BackupPath string
	Backup     BackupConfig
	Restore    RestoreConfig
}

func loadConfig() (*config, error) {
	if err := os.MkdirAll(defaultHomeDir, 0700); err != nil {
		return nil, err
	}
	configPath := filepath.Join(defaultHomeDir, "multus.conf")
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	cfg := config{
		Backup: BackupConfig{
			GZLevel: gzip.DefaultCompression,
		},
	}
	if err = yaml.UnmarshalStrict(configFile, &cfg); err != nil {
		return nil, err
	}
	for _, exclude := range cfg.Backup.Excludes {
		cfg.Backup.rExcludes = append(cfg.Backup.rExcludes,
			regexp.MustCompile(exclude))
	}
	return &cfg, nil
}
