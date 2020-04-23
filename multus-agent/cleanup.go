package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	fileRexp = regexp.MustCompile(`\.gz\.enc$`)
	hashRexp = regexp.MustCompile(`[[:xdigit:]]{64}`)
)

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

func genTimestamp(name string) (time.Time, error) {
	if len(name) < 12 {
		return time.Time{}, fmt.Errorf("invalid filename")
	}

	year, err := strconv.ParseInt(string(name[0:4]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	month, err := strconv.ParseInt(string(name[4:6]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	day, err := strconv.ParseInt(string(name[6:8]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	hour, err := strconv.ParseInt(string(name[8:10]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	min, err := strconv.ParseInt(string(name[10:12]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Date(int(year), time.Month(month), int(day), int(hour), int(min), 0, 0, time.Local), nil
}

func cleanup(ctx context.Context, storagePath string, maxSize int64) error {
	var totalSize int64
	var files Files
	err := filepath.Walk(storagePath, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		if !st.Mode().IsDir() && !st.Mode().IsRegular() {
			log.Printf("%q: unknown file -- skipping", srcPath)
			return nil
		}
		if st.Mode().IsDir() {
			return nil
		}
		totalSize += st.Size()
		fileName := filepath.Base(srcPath)
		if !strings.HasSuffix(fileName, ".gz.enc") {
			if fileName != "sig.cache" {
				log.Printf("%q: unknown file -- skipping", srcPath)
			}
			return nil
		}
		if len(fileName) < 21 {
			log.Printf("%q: invalid file -- skipping", srcPath)
			return nil
		}

		timestamp, err := genTimestamp(fileName)
		if err != nil {
			log.Printf("%q: genTimestamp: %v", srcPath, err)
			return nil
		}
		file := File{
			Path:      srcPath,
			Size:      st.Size(),
			Timestamp: timestamp,
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
	log.Printf("%+v", files)

	deletedSize := int64(0)
	curTime := files[0].Timestamp
	for _, file := range files {
		if ctx.Err() != nil {
			break
		}
		if curTime != file.Timestamp {
			if totalSize <= maxSize {
				break
			}
			curTime = file.Timestamp
		}
		log.Printf("deleting %q (%d)", file.Path, file.Size)
		if err = os.Remove(file.Path); err != nil {
			log.Printf("ERROR: Remove: %s: %v", file.Path, err)
			continue
		}
		totalSize -= file.Size
		deletedSize += file.Size
	}
	log.Printf("deleted %d bytes", deletedSize)

	return nil
}
