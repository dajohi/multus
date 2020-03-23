package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/jrick/ss/stream"
	"github.com/silvasur/golibrsync/librsync"
	"golang.org/x/sync/errgroup"
)

var (
	emptyFileAttributes = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
)

type Signature []byte

func (s Signature) IsEmpty() bool {
	return len(s) == 0
}

func (s Signature) IsEqual(sig Signature) bool {
	return bytes.Equal(s, sig)
}

func (s Signature) NewReader() *bytes.Reader {
	return bytes.NewReader(s)
}

type SignatureEntry struct {
	path      string
	signature Signature
}

func (s *SignatureEntry) Serialize() []byte {
	var offset int
	buf := make([]byte, 2+len(s.path)+8+len(s.signature))

	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(s.path)))
	offset += 2
	copy(buf[offset:], s.path)
	offset += len(s.path)
	binary.LittleEndian.PutUint64(buf[offset:offset+8], uint64(len(s.signature)))
	offset += 8
	copy(buf[offset:], s.signature)

	return buf
}

func NewSignatureEntry(path string, signature Signature) *SignatureEntry {
	return &SignatureEntry{
		path:      path,
		signature: signature,
	}
}

type SignatureCache struct {
	version    uint16
	instance   uint16
	hostname   string
	timeStamp  time.Time
	signatures map[string]Signature
}

func (sc *SignatureCache) Paths() map[string]struct{} {
	paths := make(map[string]struct{}, len(sc.signatures))
	for path := range sc.signatures {
		paths[path] = struct{}{}
	}
	return paths
}

func (sc *SignatureCache) Add(path string, signature Signature) {
	sc.signatures[path] = signature
}

func (sc *SignatureCache) Delete(path string) {
	delete(sc.signatures, path)
}

func (sc *SignatureCache) Get(path string) Signature {
	return sc.signatures[path]
}

func (sc *SignatureCache) Instance() uint16 {
	return sc.instance
}

func (sc *SignatureCache) Len() int {
	return len(sc.signatures)
}

func (sc *SignatureCache) Write(fd io.Writer) error {
	buf := make([]byte, 2+2+1+len(sc.hostname)+8+8)

	offset := 0
	binary.LittleEndian.PutUint16(buf[offset:offset+2], sc.version)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], sc.instance)
	offset += 2
	buf[offset] = byte(len(sc.hostname))
	offset++
	copy(buf[offset:offset+len(sc.hostname)], []byte(sc.hostname))
	offset += len(sc.hostname)
	binary.LittleEndian.PutUint64(buf[offset:offset+8], uint64(sc.timeStamp.Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:offset+8], uint64(len(sc.signatures)))

	if _, err := fd.Write(buf); err != nil {
		return err
	}
	for path, sig := range sc.signatures {
		if _, err := fd.Write(NewSignatureEntry(path, sig).Serialize()); err != nil {
			return err
		}
	}
	return nil
}

func LoadSignatureCache(sigfile string, maxIntervals uint16) (*SignatureCache, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	SC := SignatureCache{
		signatures: make(map[string]Signature, 204800),
		version:    FormatVersion,
	}
	buf, err := ioutil.ReadFile(sigfile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			SC.hostname = hostname
			SC.timeStamp = time.Now()
			return &SC, nil
		}
		return nil, err
	}
	if len(buf) < 14 {
		SC.hostname = hostname
		SC.timeStamp = time.Now()
		return &SC, nil
	}

	offset := 0
	SC.version = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	SC.instance = binary.LittleEndian.Uint16(buf[offset : offset+2])
	if SC.instance+1 > maxIntervals {
		SC.version = FormatVersion
		SC.instance = 0
		SC.hostname = hostname
		SC.timeStamp = time.Now()
		return &SC, nil
	}
	offset += 2
	hostLen := int(buf[offset])
	offset++
	SC.hostname = string(buf[offset : offset+hostLen])
	offset += hostLen
	SC.timeStamp = time.Unix(int64(binary.LittleEndian.Uint64(buf[offset:offset+8])), 0)
	offset += 8
	numSigs := binary.LittleEndian.Uint64(buf[offset : offset+8])
	offset += 8
	log.Printf("instance:%d numSigs:%d", SC.instance, numSigs)
	for i := 0; i < int(numSigs); i++ {
		pathLen := binary.LittleEndian.Uint16(buf[offset : offset+2])
		offset += 2
		path := string(buf[offset : offset+int(pathLen)])
		offset += int(pathLen)
		sigLen := binary.LittleEndian.Uint64(buf[offset : offset+8])
		offset += 8
		signature := make([]byte, sigLen)
		copy(signature, buf[offset:offset+int(sigLen)])
		offset += int(sigLen)

		SC.Add(path, signature)
	}
	return &SC, nil
}

type FileAttributes struct {
	Size int64
	MTim int64
	RDev uint64
	Mode uint32
	UID  uint32
	GID  uint32
}

func (f FileAttributes) IsEmpty() bool {
	return bytes.Equal(f.Serialize(), emptyFileAttributes)
}

func (f *FileAttributes) Deserialize(buf []byte) error {
	if len(buf) != 36 {
		return fmt.Errorf("invalid length: got:%d want:%d",
			len(buf), 36)
	}
	f.Size = int64(binary.LittleEndian.Uint64(buf[0:8]))
	f.MTim = int64(binary.LittleEndian.Uint64(buf[8:16]))
	f.RDev = binary.LittleEndian.Uint64(buf[16:24])
	f.Mode = binary.LittleEndian.Uint32(buf[24:28])
	f.UID = binary.LittleEndian.Uint32(buf[28:32])
	f.GID = binary.LittleEndian.Uint32(buf[32:36])

	return nil
}

func (f FileAttributes) Serialize() []byte {
	var buf [36]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(f.Size))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(f.MTim))
	binary.LittleEndian.PutUint64(buf[16:24], f.RDev)
	binary.LittleEndian.PutUint32(buf[24:28], f.Mode)
	binary.LittleEndian.PutUint32(buf[28:32], f.UID)
	binary.LittleEndian.PutUint32(buf[32:36], f.GID)

	return buf[:]
}

var (
	fSig = new(bytes.Buffer)
)

func init() {
	fSig.Grow(48)
}

func (f FileAttributes) Signature() ([]byte, error) {
	fbuf := f.Serialize()

	bufReader := bytes.NewReader(fbuf)
	fSig.Reset()
	err := librsync.CreateSignature(bufReader, fSig)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fSig.Len())
	copy(buf, fSig.Bytes())

	return buf, nil
}

type Metadata struct {
	Path    string
	Attribs FileAttributes
}

func (m *Metadata) DataLen() int64 {
	return m.Attribs.Size
}

func (m *Metadata) Serialize() []byte {
	var offset int
	pathLen := len(m.Path)
	buf := make([]byte, 2+pathLen+36)

	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(pathLen))
	offset += 2
	copy(buf[offset:offset+pathLen], m.Path)
	offset += pathLen
	copy(buf[offset:], m.Attribs.Serialize())

	return buf
}

func (m *Metadata) Signature() (Signature, error) {
	return m.Attribs.Signature()
}

func NewMetadata(filepath string) (*Metadata, error) {
	stat, err := os.Lstat(filepath)
	if err != nil {
		return nil, err
	}
	statT, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("stat returned type %T", statT)
	}

	fileAttributes := FileAttributes{
		Size: stat.Size(),
		MTim: stat.ModTime().UnixNano(),
		Mode: uint32(stat.Mode()),
		UID:  statT.Uid,
		GID:  statT.Gid,
		RDev: statT.Rdev,
	}
	MD := Metadata{
		Attribs: fileAttributes,
		Path:    filepath,
	}
	return &MD, nil
}

type Snapshot struct {
	instance     uint16
	uid          int
	gid          int
	fd           *os.File
	gz           *gzip.Writer
	pipeR        *io.PipeReader
	pipeW        *io.PipeWriter
	eg           *errgroup.Group
	bytesWritten int64
	err          error
}

func GenSignature(md *Metadata, dataReader io.ReadSeeker) (Signature, error) {
	attribSig, err := md.Signature()
	if err != nil {
		return nil, err
	}

	if dataReader != nil {
		dataSignature, err := signatureFromReader(dataReader)
		if err != nil {
			return nil, err
		}

		// signature of both attribs and data
		si := append(attribSig, dataSignature...)
		finalSig, err := signatureFromReader(bytes.NewReader(si))
		if err != nil {
			return nil, err
		}
		return finalSig, nil
	}
	return attribSig, nil
}

func (s *Snapshot) Add(md *Metadata, dataReader io.ReadSeeker, dataLen int64) (Signature, error) {
	if s.err != nil {
		return nil, s.err
	}
	numBytes, err := s.gz.Write(md.Serialize())
	s.bytesWritten += int64(numBytes)
	if err != nil {
		s.err = err
		return nil, err
	}
	attribSig, err := md.Signature()
	if err != nil {
		s.err = err
		return nil, err
	}

	var dataLenBytes [8]byte
	binary.LittleEndian.PutUint64(dataLenBytes[:], uint64(dataLen))
	numBytes, err = s.gz.Write(dataLenBytes[:])
	s.bytesWritten += int64(numBytes)
	if err != nil {
		s.err = err
		return nil, err
	}

	if dataReader != nil {
		dataSignature, err := signatureFromReader(dataReader)
		if err != nil {
			s.err = err
			return nil, err
		}

		// signature of both attribs and data
		si := append(attribSig, dataSignature...)
		finalSig, err := signatureFromReader(bytes.NewReader(si))
		if err != nil {
			s.err = err
			return nil, err
		}

		numBytes, err := io.CopyN(s.gz, dataReader, dataLen)
		s.bytesWritten += numBytes
		if err != nil {
			s.err = err
			return nil, err
		}

		if numBytes != dataLen {
			log.Printf("WARN: %q changed size during write: %d != %d",
				md.Path, dataLen, numBytes)
		}

		return finalSig, nil
	}
	return attribSig, nil
}

func (s *Snapshot) Close() error {
	if err := s.gz.Flush(); err != nil {
		s.err = err
		s.gz.Close()
		s.fd.Close()
		return err
	}
	if err := s.gz.Close(); err != nil {
		s.err = err
		s.fd.Close()
		return err
	}
	if err := s.pipeW.Close(); err != nil {
		s.err = err
		s.fd.Close()
		return err
	}
	if err := s.eg.Wait(); err != nil {
		s.err = err
		s.fd.Close()
		return err
	}
	if err := s.pipeR.Close(); err != nil {
		s.err = err
		s.fd.Close()
		return err
	}
	if err := s.fd.Close(); err != nil {
		s.err = err
		return err
	}
	if err := os.Chmod(s.fd.Name(), 0440); err != nil {
		s.err = err
		return err
	}
	if err := os.Chown(s.fd.Name(), s.uid, s.gid); err != nil {
		s.err = err
		return err
	}
	return nil
}

func (s *Snapshot) Name() string {
	return s.fd.Name()
}

func (s *Snapshot) BytesWritten() int64 {
	return s.bytesWritten
}

// SnapshotList returns a sorted list of files based on increment version.
func SnapshotList(secretKey *stream.SecretKey, dir string) (IncrementalFiles, error) {
	// Look for existing instances
	instanceFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var incrementalFiles IncrementalFiles
	for _, file := range instanceFiles {
		if filepath.Ext(file.Name()) != ".enc" {
			continue
		}
		fileName := filepath.Join(dir, file.Name())
		fd, err := os.Open(fileName)
		if err != nil {
			return nil, err
		}

		header, err := stream.ReadHeader(fd)
		if err != nil {
			fd.Close()
			return nil, err
		}
		symKey, err := stream.Decapsulate(header, secretKey)
		if err != nil {
			fd.Close()
			return nil, err
		}

		pipeR, pipeW := io.Pipe()
		eg, _ := errgroup.WithContext(context.Background())
		eg.Go(func() error {
			gzR, err := gzip.NewReader(pipeR)
			if err != nil {
				return err
			}
			defer gzR.Close()
			b := new(bytes.Buffer)
			if _, err = io.CopyN(b, gzR, 3); err != nil {
				return err
			}
			hostLen := int64(b.Bytes()[2])
			if _, err = io.CopyN(b, gzR, hostLen+8+2); err != nil {
				return err
			}
			if _, err = io.Copy(ioutil.Discard, pipeR); err != nil {
				return err
			}
			var iFile IncrementalFile
			offset := int64(3)
			iFile.Hostname = string(b.Bytes()[offset : offset+hostLen])
			offset += hostLen
			iFile.Timestamp = time.Unix(int64(binary.LittleEndian.Uint64(b.Bytes()[offset:offset+8])), 0)
			offset += 8
			iFile.Increment = binary.LittleEndian.Uint16(b.Bytes()[offset : offset+2])
			iFile.Filename = fileName
			incrementalFiles = append(incrementalFiles, iFile)
			return nil
		})
		err = stream.Decrypt(pipeW, fd, header.Bytes, symKey)
		if err != nil {
			pipeW.Close()
			pipeR.Close()
			fd.Close()
			return nil, err
		}
		pipeW.Close()
		err = eg.Wait()
		pipeR.Close()
		if err != nil {
			fd.Close()
			return nil, err
		}
		if err = fd.Close(); err != nil {
			return nil, err
		}
	}

	check := make(map[string]IncrementalFiles)
	for _, incFile := range incrementalFiles {
		checkid, exists := check[incFile.Hostname+incFile.Timestamp.String()]
		if !exists {
			check[incFile.Hostname+incFile.Timestamp.String()] = append(check[incFile.Hostname+incFile.Timestamp.String()], incFile)
			continue
		}
		for _, inc := range checkid {
			if inc.Increment == incFile.Increment {
				return nil, fmt.Errorf("increment '%d' found twice: %q %q",
					inc.Increment, incFile.Filename, inc.Filename)
			}
		}
		check[incFile.Hostname+incFile.Timestamp.String()] = append(check[incFile.Hostname+incFile.Timestamp.String()], incFile)
	}
	sort.Sort(incrementalFiles)

	return incrementalFiles, nil
}

type IncrementalFile struct {
	Hostname  string
	Timestamp time.Time
	Increment uint16
	Filename  string
}

type IncrementalFiles []IncrementalFile

func (i IncrementalFiles) Len() int {
	return len(i)
}

func (i IncrementalFiles) Less(a, b int) bool {
	return i[a].Increment < i[b].Increment
}

func (i IncrementalFiles) Swap(a, b int) {
	i[a], i[b] = i[b], i[a]
}

func NewSnapshot(pubKey *stream.PublicKey, uid, gid, gzLevel int, dataDir, hostname string,
	timeStamp time.Time, instance uint16, version uint16) (*Snapshot, error) {

	header, symKey, err := stream.Encapsulate(rand.Reader, pubKey)
	if err != nil {
		return nil, err
	}

	d := fmt.Sprintf("%d%02d%02d%02d%02d", timeStamp.Year(), timeStamp.Month(), timeStamp.Day(), timeStamp.Hour(), timeStamp.Minute())
	filename := filepath.Join(dataDir, fmt.Sprintf("%s-%s.%d.gz.enc", d, hostname, instance))
	fd, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	pipeR, pipeW := io.Pipe()
	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		return stream.Encrypt(fd, pipeR, header, symKey)
	})
	gz, err := gzip.NewWriterLevel(pipeW, gzLevel)
	if err != nil {
		pipeW.Close()
		pipeR.Close()
		fd.Close()
		os.Remove(fd.Name())
		return nil, err
	}

	hostLen := len(hostname)
	b := make([]byte, 2+1+hostLen+8+2)

	offset := 0
	binary.LittleEndian.PutUint16(b[offset:offset+2], version)
	offset += 2
	b[offset] = byte(hostLen)
	offset++
	copy(b[offset:offset+hostLen], []byte(hostname))
	offset += hostLen
	binary.LittleEndian.PutUint64(b[offset:offset+8], uint64(timeStamp.Unix()))
	offset += 8
	binary.LittleEndian.PutUint16(b[offset:offset+2], instance)

	numBytes, err := gz.Write(b)
	if err != nil {
		gz.Close()
		pipeW.Close()
		pipeR.Close()
		fd.Close()
		os.Remove(fd.Name())
		return nil, err
	}

	return &Snapshot{
		instance:     instance,
		uid:          uid,
		gid:          gid,
		fd:           fd,
		gz:           gz,
		pipeW:        pipeW,
		pipeR:        pipeR,
		eg:           eg,
		bytesWritten: int64(numBytes),
	}, nil
}
