package main

import (
	"bytes"
	"io"
	"os"

	"github.com/silvasur/golibrsync/librsync"
)

func isCharDevice(filemode os.FileMode) bool {
	return filemode&os.ModeCharDevice == os.ModeCharDevice
}

func isDevice(filemode os.FileMode) bool {
	return filemode&os.ModeDevice == os.ModeDevice
}

func isDir(filemode os.FileMode) bool {
	return filemode&os.ModeDir == os.ModeDir
}

func isNamedPipe(filemode os.FileMode) bool {
	return filemode&os.ModeNamedPipe == os.ModeNamedPipe
}

func isSocket(filemode os.FileMode) bool {
	return filemode&os.ModeSocket == os.ModeSocket
}

func isSymlink(filemode os.FileMode) bool {
	return filemode&os.ModeSymlink == os.ModeSymlink
}

func major(rdev uint64) uint64 {
	return (rdev >> 8) & 0xff
}

func minor(rdev uint64) uint64 {
	return (rdev & 0xff) | ((rdev & 0xffff0000) >> 8)
}

var (
	sigS = new(bytes.Buffer)
)

func init() {
	sigS.Grow(1024 * 1024 * 10)
}

func signatureFromReader(fd io.ReadSeeker) (Signature, error) {
	// Save the current offset
	savedOffset, err := fd.Seek(0, 1)
	if err != nil {
		return nil, err
	}

	// Create signature of the source file
	sigS.Reset()
	err = librsync.CreateSignature(fd, sigS)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, sigS.Len())
	copy(buf, sigS.Bytes())

	if sigS.Cap() > 1024*1024*10 {
		sigS = new(bytes.Buffer)
		sigS.Grow(1024 * 1024 * 10)
	}

	// Return cursor to the original offset
	_, err = fd.Seek(savedOffset, 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func zero(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0x00
	}
}
