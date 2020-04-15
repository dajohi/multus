package main

import (
	"bytes"
	"io"
	"os"

	"github.com/smtc/rsync"
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

func signatureFromReader(dstBuf *bytes.Buffer, fd io.ReadSeeker, len int64) error {
	// Save the current offset
	savedOffset, err := fd.Seek(0, 1)
	if err != nil {
		return err
	}

	// Create signature of the source file
	err = rsync.GenSign(fd, len, 2048, dstBuf)
	if err != nil {
		return err
	}

	// Return cursor to the original offset
	_, err = fd.Seek(savedOffset, 0)
	return err
}

func zero(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0x00
	}
}
