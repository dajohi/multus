package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jrick/ss/stream"
	"github.com/silvasur/golibrsync/librsync"
)

func lookupGroup(groupName string) (int, error) {
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return -1, err
	}
	gid, err := strconv.ParseInt(group.Gid, 10, 64)
	if err != nil {
		return -1, err
	}
	return int(gid), nil
}

func backup(ctx context.Context, pubKey *stream.PublicKey, cfg *config) error {
	destDir := filepath.Clean(cfg.BackupPath)
	destDirAbs, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}

	gid, err := lookupGroup(cfg.Backup.Group)
	if err != nil {
		return err
	}
	uid := os.Geteuid()

	err = os.MkdirAll(destDir, 0750)
	if err != nil {
		return err
	}
	err = os.Chown(destDir, uid, gid)
	if err != nil {
		return err
	}

	sigFile := filepath.Join(destDir, "sig.cache")
	existingSC, err := LoadSignatureCache(sigFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var sc *SignatureCache
	if existingSC == nil || existingSC.Instance()+1 > cfg.Backup.MaxIntervals {
		sc, err = NewSignatureCache(filepath.Join(destDir, "sig.cache.inprogress"), time.Now(), 0)
	} else {
		sc, err = NewSignatureCache(filepath.Join(destDir, "sig.cache.inprogress"), existingSC.timeStamp, existingSC.Instance()+1)
	}
	if err != nil {
		return err
	}

	pathsToCheck := existingSC.Paths()

	log.Printf("----------  RUNNING LEVEL %d (%v) -----------", sc.instance, sc.timeStamp)

	snap, err := NewSnapshot(pubKey, uid, gid, cfg.Backup.GZLevel, destDir, sc.hostname, sc.timeStamp, sc.instance, sc.version)
	if err != nil {
		return err
	}

	delta := new(bytes.Buffer)
	delta.Grow(1024 * 1024 * 10)

	startTime := time.Now()
	filesExcluded := int32(0)
	for _, sourceDir := range cfg.Backup.Paths {
		err = filepath.Walk(sourceDir, func(srcRelPath string, info os.FileInfo, err error) error {
			if delta.Cap() > 1024*1024*10 {
				delta = new(bytes.Buffer)
				delta.Grow(1024 * 1024 * 10)
			}
			if err != nil {
				log.Printf("Walk: %v", err)
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}

			srcPath, err := filepath.Abs(srcRelPath)
			if err != nil {
				return err
			}

			// do not backup destination directory
			if strings.HasPrefix(srcPath, destDirAbs) {
				return nil
			}

			for _, exclude := range cfg.Backup.rExcludes {
				if exclude.MatchString(srcPath) {
					filesExcluded++
					log.Printf("%q: excluding", srcPath)
					return nil
				}
			}

			MD, err := NewMetadata(srcPath)
			if err != nil {
				return err
			}

			fileMode := os.FileMode(MD.Attribs.Mode)
			currentSig, err := existingSC.Get(srcPath)
			if err != nil {
				return err
			}

			switch {
			case isSocket(fileMode):
				log.Printf("skipping socket file: %v", srcPath)
				return nil
			case isCharDevice(fileMode):
				fallthrough
			case isDevice(fileMode):
				fallthrough
			case isNamedPipe(fileMode):
				fallthrough
			case isDir(fileMode):
				thisSig, err := GenSignature(MD, nil)
				if err != nil {
					return err
				}
				if !bytes.Equal(currentSig, thisSig) {
					if !currentSig.IsEmpty() {
						log.Printf("%q changed", srcPath)
					} else {
						log.Printf("%q new file", srcPath)
					}
					thisSig, err = snap.Add(MD, nil, 0)
					if err != nil {
						return err
					}
					sc.Add(srcPath, thisSig)
				} else {
					log.Printf("%q no change", srcPath)
					sc.Add(srcPath, currentSig)
				}
				delete(pathsToCheck, srcPath)
				return nil
			case isSymlink(fileMode):
				dest, err := os.Readlink(srcPath)
				if err != nil {
					return err
				}
				dataReader := bytes.NewReader([]byte(dest))
				thisSig, err := GenSignature(MD, dataReader)
				if err != nil {
					return err
				}
				if !bytes.Equal(currentSig, thisSig) {
					if !currentSig.IsEmpty() {
						log.Printf("%q changed", srcPath)

						delta.Reset()
						err = librsync.CreateDelta(currentSig.NewReader(), dataReader, delta)
						if err != nil {
							return err
						}
						dataReader.Reset(delta.Bytes())
					} else {
						log.Printf("%q new file", srcPath)
					}
					thisSig, err = snap.Add(MD, dataReader, int64(dataReader.Len()))
					if err != nil {
						return err
					}
					sc.Add(srcPath, thisSig)
				} else {
					log.Printf("%q: no change", srcPath)
					sc.Add(srcPath, currentSig)
				}
				delete(pathsToCheck, srcPath)
				return nil
			default:
				srcFD, err := os.Open(srcPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Open: %v\n", err)
					return nil
				}
				thisSig, err := GenSignature(MD, srcFD)
				if err != nil {
					srcFD.Close()
					return err
				}
				if !bytes.Equal(currentSig, thisSig) {
					if !currentSig.IsEmpty() {
						log.Printf("%q: changed", srcPath)
						delta.Reset()
						err = librsync.CreateDelta(currentSig.NewReader(), srcFD, delta)
						if err != nil {
							return err
						}
						thisSig, err = snap.Add(MD, bytes.NewReader(delta.Bytes()),
							int64(len(delta.Bytes())))
					} else {
						log.Printf("%q new file", srcPath)
						st, err := srcFD.Stat()
						if err != nil {
							return err
						}
						thisSig, err = snap.Add(MD, srcFD, st.Size())
						if err != nil {
							return err
						}
					}
					if err != nil {
						srcFD.Close()
						return err
					}
					sc.Add(srcPath, thisSig)
				} else {
					log.Printf("%q: no change", srcPath)
					sc.Add(srcPath, currentSig)
				}
				srcFD.Close()
				delete(pathsToCheck, srcPath)
				return nil
			}
		})
		if err != nil {
			snap.Close()
			os.Remove(snap.Name())
			return fmt.Errorf("error walking the path %q: %v", sourceDir, err)
		}
	}

	// handle deleted files
	for deletedFilePath := range pathsToCheck {
		log.Printf("%q: deleted", deletedFilePath)
		_, err = snap.Add(&Metadata{Path: deletedFilePath, Attribs: FileAttributes{}}, nil, 0)
		if err != nil {
			snap.Close()
			os.Remove(snap.Name())
			return err
		}
	}

	if err = snap.Close(); err != nil {
		os.Remove(snap.Name())
		return err
	}

	if err = sc.Close(); err != nil {
		return err
	}
	if err = existingSC.Close(); err != nil {
		return err
	}
	if err = os.Rename(sc.fd.Name(), sigFile); err != nil {
		return err
	}
	err = os.Chown(sigFile, uid, gid)
	if err != nil {
		log.Printf("%v", err)
	}

	log.Printf("completed: duration:%v bytes written:%d files-skipped:%d",
		time.Since(startTime), snap.BytesWritten(), filesExcluded)
	return nil
}
