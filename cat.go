package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/jrick/ss/stream"
	"golang.org/x/sync/errgroup"
)

func cat(ctx context.Context, secretKey *stream.SecretKey, file string) error {
	dataFile, err := os.Open(file)
	if err != nil {
		return err
	}
	defer dataFile.Close()

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
	defer dataFileGZ.Close() // REMOVE

	b := new(bytes.Buffer)
	if _, err := io.CopyN(b, dataFileGZ, 3); err != nil {
		dataFileGZ.Close()
		pipeR.Close()
		return err
	}
	hostLen := int64(b.Bytes()[2])
	b.Reset()
	if _, err := io.CopyN(b, dataFileGZ, hostLen+8+2); err != nil {
		dataFileGZ.Close()
		pipeR.Close()
		return err
	}
	buf := b.Bytes()
	hostname := string(buf[0:hostLen])
	t := time.Unix(int64(binary.LittleEndian.Uint64(buf[hostLen:hostLen+8])), 0)
	tmpInc := binary.LittleEndian.Uint16(buf[hostLen+8 : hostLen+8+2])

	fmt.Printf(" Hostname: %v\n", hostname)
	fmt.Printf("Timestamp: %v\n", t)
	fmt.Printf("Increment: %d\n", tmpInc)

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
		path := b.String()
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
			fmt.Printf("%q: delete", path)
			continue
		}

		fileMode := os.FileMode(attrib.Mode)
		switch {
		case isSocket(fileMode):
			fmt.Printf("%q: socket\n", path)
		case isCharDevice(fileMode):
			fmt.Printf("%q: character device\n", path)
		case isDevice(fileMode):
			fmt.Printf("%q: block device\n", path)
		case isNamedPipe(fileMode):
			fmt.Printf("%q: named pipe\n", path)
		case isDir(fileMode):
			fmt.Printf("%q: directory\n", path)
		case isSymlink(fileMode):
			fmt.Printf("%q: symlink (%d)\n", path, dataLen)
		default:
			fmt.Printf("%q: file (%d)\n", path, dataLen)
			if _, err = io.CopyN(ioutil.Discard, dataFileGZ, int64(dataLen)); err != nil {
				dataFileGZ.Close()
				pipeR.Close()
				return err
			}
			continue
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

	return nil
}
