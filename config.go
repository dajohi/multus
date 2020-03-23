package main

import (
	"compress/gzip"
	"io/ioutil"
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
	BackupPath string
	Backup     BackupConfig
	Restore    RestoreConfig
}

func loadConfig() (*config, error) {
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
