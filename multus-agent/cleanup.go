package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"
)

var (
	fileRexp = regexp.MustCompile(`\.gz\.enc$`)
	hashRexp = regexp.MustCompile(`[[:xdigit:]]{64}`)
)

type Cleanup struct {
	Timestamp time.Time
	Files     map[string]os.FileInfo
}

type File struct {
	Path      string
	Timestamp time.Time
	Size      int64
}

type Files []File

func (f Files) Len() int {
	return len(f)
}

func (f Files) Less(a, b int) bool {
	return f[a].Timestamp.Before(f[b].Timestamp)
}

func (f Files) Swap(a, b int) {
	f[a], f[b] = f[b], f[a]
}

func cleanup(storagePath string, maxSize int64) error {
	var totalSize int64
	now := time.Now()
	var files Files
	err := filepath.Walk(storagePath, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		if !st.Mode().IsDir() && !st.Mode().IsRegular() {
			return err
		}
		if st.Mode().IsDir() {
			return nil
		}
		sysStat, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat returned type %T", st.Sys())
		}
		file := File{
			Path:      srcPath,
			Size:      st.Size(),
			Timestamp: time.Unix(sysStat.Ctim.Sec, sysStat.Ctim.Nsec),
		}
		totalSize += file.Size
		fileName := filepath.Base(srcPath)
		if !fileRexp.MatchString(fileName) {
			if fileName != "sig.cache" {
				log.Printf("%q: unknown file", srcPath)
			}
			return nil
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return err
	}
	log.Printf("total size: %d bytes, max size: %d bytes", totalSize, maxSize)
	if totalSize <= maxSize {
		return nil
	}
	log.Printf("doing cleanup...")

	sort.Sort(files)
	hashes := make(map[string]time.Duration)
	for _, file := range files {
		fileHash := hashRexp.FindString(filepath.Base(file.Path))
		fileAge := now.Sub(file.Timestamp)

		if age, exists := hashes[fileHash]; exists {
			if fileAge > age {
				hashes[fileHash] = fileAge
			}
			continue
		}
		hashes[fileHash] = fileAge
	}

	for hash, age := range hashes {
		var size int64
		for _, file := range files {
			fileHash := hashRexp.FindString(filepath.Base(file.Path))
			if fileHash != hash {
				continue
			}
			size += file.Size
			totalSize -= file.Size
			log.Printf("%q: delete", file.Path)
		}
		log.Printf("%s: deleted %d bytes, age: %v", hash, size, age)
		if totalSize <= maxSize {
			break
		}
	}

	return nil
}
