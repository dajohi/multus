package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jrick/ss/stream"
	"github.com/silvasur/golibrsync/librsync"
	"golang.org/x/sync/errgroup"
)

func restore(ctx context.Context, secretKey *stream.SecretKey, sourceDir, destDir string, fileRegexp *regexp.Regexp, level int32) error {
	insts, err := SnapshotList(secretKey, sourceDir)
	if err != nil {
		return err
	}
	if len(insts) == 0 {
		return fmt.Errorf("no backups found")
	}

	idx := 0
	snapList := make(map[time.Time]int)
	for _, inst := range insts {
		i, exists := snapList[inst.Timestamp]
		if !exists {
			snapList[inst.Timestamp] = idx
			idx++
			continue
		}
		if i > idx {
			snapList[inst.Timestamp] = i
		}
	}

	snapID := insts[0].Timestamp
	if len(snapList) > 1 {
		fmt.Println("snapshots:")
		for ts, idx := range snapList {
			fmt.Printf("%d: %v\n", idx, ts)
		}
		reader := bufio.NewReader(os.Stdin)
		fmt.Fprintf(os.Stderr, "enter id to restore: ")
		os.Stderr.Sync()
		t, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		t = strings.Replace(t, "\n", "", -1)
		fmt.Fprint(os.Stderr, "\n")

		u, err := strconv.ParseUint(t, 10, 64)
		if err != nil {
			return err
		}
		var found bool
		for ts, idx := range snapList {
			if uint64(idx) == u {
				snapID = ts
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid id '%d'", u)
		}
	}

	var maxLevel int32
	for _, inst := range insts {
		if inst.Timestamp == snapID {
			maxLevel++
		}
	}

	if level < 0 || level > maxLevel {
		level = maxLevel
	}

	log.Printf("Restoring to level %d...", level)
	startTime := time.Now()
	for _, inst := range insts {
		if inst.Timestamp != snapID {
			log.Printf("skipping %s", inst.Filename)
			continue
		}
		if inst.Increment > uint16(level) {
			break
		}
		//isLastLevel := inst.Instance == level

		log.Printf("----------  APPLYING LEVEL %d  -----------", inst.Increment)
		log.Printf("file: %q", inst.Filename)
		dataFile, err := os.Open(inst.Filename)
		if err != nil {
			return err
		}
		header, err := stream.ReadHeader(dataFile)
		if err != nil {
			dataFile.Close()
			return err
		}
		symKey, err := stream.Decapsulate(header, secretKey)
		if err != nil {
			dataFile.Close()
			return err
		}

		pipeR, pipeW := io.Pipe()
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			defer dataFile.Close()
			err = stream.Decrypt(pipeW, dataFile, header.Bytes, symKey)
			if err != nil {
				pipeW.Close()
				return err
			}
			return pipeW.Close()
		})
		dataFileGZ, err := gzip.NewReader(pipeR)
		if err != nil {
			pipeR.Close()
			pipeW.Close()
			return err
		}

		b := new(bytes.Buffer)
		if _, err := io.CopyN(b, dataFileGZ, 3); err != nil {
			dataFileGZ.Close()
			pipeR.Close()
			return err
		}
		hostLen := int64(b.Bytes()[2])
		b.Reset()
		b.Grow(1024 * 1024)
		if _, err := io.CopyN(b, dataFileGZ, hostLen+8+2); err != nil {
			dataFileGZ.Close()
			pipeR.Close()
			return err
		}
		buf := b.Bytes()
		if snapID != time.Unix(int64(binary.LittleEndian.Uint64(buf[hostLen:hostLen+8])), 0) {
			dataFileGZ.Close()
			pipeR.Close()
			return nil
		}
		tmpInc := binary.LittleEndian.Uint16(buf[hostLen+8 : hostLen+8+2])
		if tmpInc != inst.Increment {
			dataFileGZ.Close()
			pipeR.Close()
			return fmt.Errorf("%q inconsistency: got:%d expected:%d",
				inst.Filename, tmpInc, inst.Increment)
		}
		for {
			if ctx.Err() != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return ctx.Err()
			}
			b.Reset()
			if _, err := io.CopyN(b, dataFileGZ, 2); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			pathLen := binary.LittleEndian.Uint16(b.Bytes()[0:2])
			b.Reset()
			if _, err := io.CopyN(b, dataFileGZ, int64(pathLen)); err != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			path := filepath.Join(destDir, b.String())
			extract := true
			if fileRegexp != nil && !fileRegexp.MatchString(b.String()) {
				extract = false
			}
			b.Reset()
			if _, err := io.CopyN(b, dataFileGZ, 36); err != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			var attrib FileAttributes
			if err = attrib.Deserialize(b.Bytes()); err != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			b.Reset()

			if _, err := io.CopyN(b, dataFileGZ, 8); err != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			dataLen := binary.LittleEndian.Uint64(b.Bytes()[0:8])
			b.Reset()

			if attrib.IsEmpty() {
				log.Printf("%q: deleting file", path)
				err = os.Remove(path)
				if err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					return err
				}
				continue
			}

			fileMode := os.FileMode(attrib.Mode)
			switch {
			case isSocket(fileMode):
				fallthrough
			case isCharDevice(fileMode):
				fallthrough
			case isDevice(fileMode):
				if !extract {
					continue
				}
				log.Printf("%q: unsupported file", path)
				continue
			case isNamedPipe(fileMode):
				if !extract {
					continue
				}
				err = syscall.Mkfifo(path, 0o0600)
				if err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					return err
				}
				if err = os.Chmod(path, fileMode.Perm()); err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					os.Remove(path)
					return err
				}
				if err = os.Chown(path, int(attrib.UID), int(attrib.GID)); err != nil {
					log.Printf("%v", err)
				}

				continue
			case isDir(fileMode):
				if !extract {
					continue
				}
				err = os.MkdirAll(path, fileMode)
				if err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					return err
				}
				continue
			case isSymlink(fileMode):
				if _, err = io.CopyN(b, dataFileGZ, int64(dataLen)); err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					return err
				}
				if !extract {
					continue
				}
				if st, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
					log.Printf("%q: new symlink -> %s", path, b.Bytes())
					err = os.Symlink(b.String(), path)
					if err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						return err
					}
				} else {
					log.Printf("%q: patching [symlink]", path)

					reader := bytes.NewReader(b.Bytes())
					target := new(bytes.Buffer)
					if isSymlink(st.Mode()) {
						currentDelta, err := os.Readlink(path)
						if err != nil {
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
						basis := bytes.NewReader([]byte(currentDelta))
						if err = librsync.Patch(basis, reader, target); err != nil {
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
					} else {
						basis, err := os.Open(path)
						if err != nil {
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
						if err = librsync.Patch(basis, reader, target); err != nil {
							basis.Close()
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
						basis.Close()
					}
					if err = os.Remove(path); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						return err
					}
					if err = os.Symlink(target.String(), path); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						return err
					}
				}
			default:
				if !extract {
					if _, err = io.CopyN(ioutil.Discard, dataFileGZ, int64(dataLen)); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						return err
					}
					continue
				}
				if fileRegexp != nil {
					fileDir := filepath.Dir(path)
					if _, err := os.Stat(fileDir); err != nil {
						if !os.IsNotExist(err) {
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
						err = os.MkdirAll(fileDir, 0o0755)
						if err != nil {
							dataFileGZ.Close()
							pipeR.Close()
							return err
						}
					}
				}

				tmpFile, err := os.OpenFile(path+".partial", os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					return err
				}
				if _, err = os.Stat(path); errors.Is(err, os.ErrNotExist) {
					log.Printf("%q: new file", path)
					if _, err = io.CopyN(tmpFile, dataFileGZ, int64(dataLen)); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						tmpFile.Close()
						os.Remove(tmpFile.Name())
						return err
					}
				} else {
					log.Printf("%q: patching", path)
					buf := new(bytes.Buffer)
					buf.Grow(int(dataLen))
					if _, err = io.CopyN(buf, dataFileGZ, int64(dataLen)); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						tmpFile.Close()
						os.Remove(tmpFile.Name())
						return err
					}

					basis, err := os.Open(path)
					if err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						tmpFile.Close()
						os.Remove(tmpFile.Name())
						return err
					}

					reader := bytes.NewReader(buf.Bytes())
					if err = librsync.Patch(basis, reader, tmpFile); err != nil {
						basis.Close()
						dataFileGZ.Close()
						pipeR.Close()
						tmpFile.Close()
						os.Remove(tmpFile.Name())
						return err
					}
					basis.Close()
				}
				if err = tmpFile.Close(); err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					os.Remove(tmpFile.Name())
					return err
				}
				if err = os.Rename(tmpFile.Name(), path); err != nil {
					dataFileGZ.Close()
					pipeR.Close()
					os.Remove(tmpFile.Name())
					return err
				}
				if !isSymlink(fileMode) {
					if err = os.Chmod(path, fileMode.Perm()); err != nil {
						dataFileGZ.Close()
						pipeR.Close()
						os.Remove(path)
						return err
					}
					if err = os.Chown(path, int(attrib.UID), int(attrib.GID)); err != nil {
						log.Printf("%v", err)
					}
				}
			}
		}
		if err := eg.Wait(); err != nil {
			dataFileGZ.Close()
			pipeR.Close()
			return err
		}
		if err = dataFileGZ.Close(); err != nil {
			pipeR.Close()
			return err
		}
		pipeR.Close()
	}
	log.Printf("completed in %v", time.Since(startTime))
	return nil
}
