// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build unix

package wasip1

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/ziggy42/epsilon/epsilon"
)

var errMaxFileDescriptorsReached = errors.New("max file descriptors reached")

const maxFileDescriptors = 2048

type wasiFileDescriptor struct {
	file             *os.File
	fileType         uint8
	flags            uint16
	rights           int64
	rightsInheriting int64
	guestPath        string
	isPreopen        bool
}

func (fd *wasiFileDescriptor) close() {
	if fd.file != os.Stdin && fd.file != os.Stdout && fd.file != os.Stderr {
		fd.file.Close()
	}
}

type wasiResourceTable struct {
	fds map[int32]*wasiFileDescriptor
}

func (rt *wasiResourceTable) closeAll() {
	for _, fd := range rt.fds {
		fd.close()
	}
}

func newWasiResourceTable(preopens []WasiPreopen) (*wasiResourceTable, error) {
	stdRights := RightsFdFilestatGet | RightsPollFdReadwrite
	stdin, err := newStdFileDescriptor(os.Stdin, RightsFdRead|stdRights)
	if err != nil {
		return nil, err
	}
	stdout, err := newStdFileDescriptor(os.Stdout, RightsFdWrite|stdRights)
	if err != nil {
		return nil, err
	}
	stderr, err := newStdFileDescriptor(os.Stderr, RightsFdWrite|stdRights)
	if err != nil {
		return nil, err
	}

	resourceTable := &wasiResourceTable{
		fds: map[int32]*wasiFileDescriptor{0: stdin, 1: stdout, 2: stderr},
	}

	for _, dir := range preopens {
		fd, err := newPreopenFileDescriptor(dir)
		if err != nil {
			// If we fail halfway through loop, we must close the preopened files we
			// already accepted.
			resourceTable.closeAll()
			return nil, err
		}
		newFdIndex, err := resourceTable.allocateFdIndex()
		if err != nil {
			resourceTable.closeAll()
			dir.File.Close()
			return nil, err
		}
		resourceTable.fds[newFdIndex] = fd
	}
	return resourceTable, nil
}

func newFileDescriptor(
	file *os.File,
	rights, rightsInheriting int64,
	flags uint16,
) (*wasiFileDescriptor, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		rights &= ^(RightsFdSeek | RightsFdTell | RightsFdRead | RightsFdWrite)
	}

	return &wasiFileDescriptor{
		file:             file,
		fileType:         getModeFileType(info.Mode()),
		flags:            flags,
		rights:           rights,
		rightsInheriting: rightsInheriting,
		guestPath:        "",
		isPreopen:        false,
	}, nil
}

func newPreopenFileDescriptor(pre WasiPreopen) (*wasiFileDescriptor, error) {
	fd, err := newFileDescriptor(pre.File, pre.Rights, pre.RightsInheriting, 0)
	if err != nil {
		return nil, err
	}
	fd.guestPath = pre.GuestPath
	fd.isPreopen = true
	return fd, nil
}

func newStdFileDescriptor(
	file *os.File,
	rights int64,
) (*wasiFileDescriptor, error) {
	return newFileDescriptor(file, rights, 0, 0)
}

func (w *wasiResourceTable) advise(
	fdIndex int32,
	offset, length int64,
	advice int32,
) int32 {
	if _, ok := w.fds[fdIndex]; !ok {
		return errnoBadF
	}
	// This WASI implementation does not use the hints provided by this API.
	return errnoSuccess
}

func (w *wasiResourceTable) allocate(
	fdIndex int32,
	offset, length int64,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdAllocate)
	if errCode != errnoSuccess {
		return errCode
	}

	info, err := fd.file.Stat()
	if err != nil {
		return mapError(err)
	}

	targetSize := offset + length
	if targetSize <= info.Size() {
		return errnoSuccess
	}

	if err := fd.file.Truncate(targetSize); err != nil {
		return mapError(err)
	}

	return errnoSuccess
}

func (w *wasiResourceTable) close(fdIndex int32) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}
	fd.close()
	delete(w.fds, fdIndex)
	return errnoSuccess
}

func (w *wasiResourceTable) dataSync(fdIndex int32) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}
	if err := fd.file.Sync(); err != nil {
		return mapError(err)
	}
	return errnoSuccess
}

func (w *wasiResourceTable) getStat(
	memory *epsilon.Memory,
	fdIndex, fdStatPtr int32,
) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}

	err := memory.StoreByte(0, uint32(fdStatPtr), uint8(fd.fileType))
	if err != nil {
		return errnoFault
	}
	err = memory.StoreUint16(0, uint32(fdStatPtr+2), fd.flags)
	if err != nil {
		return errnoFault
	}
	err = memory.StoreUint64(0, uint32(fdStatPtr+8), uint64(fd.rights))
	if err != nil {
		return errnoFault
	}
	err = memory.StoreUint64(0, uint32(fdStatPtr+16), uint64(fd.rightsInheriting))
	if err != nil {
		return errnoFault
	}
	return errnoSuccess
}

func (w *wasiResourceTable) setStatFlags(fdIndex, fdFlags int32) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) setStatRights(
	fdIndex int32,
	rightsBase, rightsInheriting int64,
) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}

	// Can only remove rights, not add them
	if (rightsBase & ^fd.rights) != 0 {
		return errnoNotCapable
	}
	if (rightsInheriting & ^fd.rightsInheriting) != 0 {
		return errnoNotCapable
	}

	fd.rights = rightsBase
	fd.rightsInheriting = rightsInheriting
	return errnoSuccess
}

func (w *wasiResourceTable) getFileStat(
	memory *epsilon.Memory,
	fdIndex, bufPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) setFileStatSize(fdIndex int32, size int64) int32 {
	fd, errCode := w.getFileOrDir(fdIndex, RightsFdFilestatSetSize)
	if errCode != errnoSuccess {
		return errCode
	}

	if err := fd.file.Truncate(size); err != nil {
		return mapError(err)
	}
	return errnoSuccess
}

func (w *wasiResourceTable) setFileStatTimes(
	fdIndex int32,
	atim, mtim int64,
	fstFlags int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pread(
	memory *epsilon.Memory,
	fdIndex, iovecPtr, iovecLength int32,
	offset int64,
	nPtr int32,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdRead)
	if errCode != errnoSuccess {
		return errCode
	}

	readBytes := func(buf []byte, readSoFar int64) (int, error) {
		return fd.file.ReadAt(buf, offset+readSoFar)
	}

	return iterIovec(memory, iovecPtr, iovecLength, nPtr, readBytes)
}

func (w *wasiResourceTable) getPrestat(
	memory *epsilon.Memory,
	fdIndex, prestatPtr int32,
) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}

	if !fd.isPreopen {
		return errnoBadF
	}

	// Note: WASI Preview 1 only supports "Directory" preopens. If the underlying
	// file is a socket or other resource, we must present it as a directory.
	// Guests attempting to open paths under this FD will fail with ENOTDIR.
	err := memory.StoreByte(0, uint32(prestatPtr), preopenTypeDir)
	if err != nil {
		return errnoFault
	}
	err = memory.StoreUint32(0, uint32(prestatPtr+4), uint32(len(fd.guestPath)))
	if err != nil {
		return errnoFault
	}

	return errnoSuccess
}

func (w *wasiResourceTable) prestatDirName(
	memory *epsilon.Memory,
	fdIndex, pathPtr, pathLen int32,
) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok || !fd.isPreopen {
		return errnoBadF
	}

	if int32(len(fd.guestPath)) > pathLen {
		return errnoNameTooLong
	}

	if err := memory.Set(0, uint32(pathPtr), []byte(fd.guestPath)); err != nil {
		return errnoFault
	}

	return errnoSuccess
}

func (w *wasiResourceTable) pwrite(
	memory *epsilon.Memory,
	fdIndex, ciovecPtr, ciovecLength int32,
	offset int64,
	nPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) read(
	memory *epsilon.Memory,
	fdIndex, iovecPtr, iovecLength, nPtr int32,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdRead)
	if errCode != errnoSuccess {
		return errCode
	}

	readBytes := func(buf []byte, _ int64) (int, error) {
		return fd.file.Read(buf)
	}

	return iterIovec(memory, iovecPtr, iovecLength, nPtr, readBytes)
}

func (w *wasiResourceTable) readdir(
	memory *epsilon.Memory,
	fdIndex, bufPtr, bufLen int32,
	cookie int64,
	bufusedPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) renumber(fdIndex, toFdIndex int32) int32 {
	if fdIndex == toFdIndex {
		return errnoSuccess
	}

	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}

	toFd, exists := w.fds[toFdIndex]
	if !exists {
		return errnoBadF
	}

	toFd.close()
	w.fds[toFdIndex] = fd
	delete(w.fds, fdIndex)
	return errnoSuccess
}

func (w *wasiResourceTable) seek(
	memory *epsilon.Memory,
	fdIndex int32,
	offset int64,
	whence, newOffsetPtr int32,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdSeek)
	if errCode != errnoSuccess {
		return errCode
	}

	var goWhence int
	switch uint8(whence) {
	case whenceSet:
		goWhence = io.SeekStart
	case whenceCur:
		goWhence = io.SeekCurrent
	case whenceEnd:
		goWhence = io.SeekEnd
	default:
		return errnoInval
	}

	newOffset, err := fd.file.Seek(offset, goWhence)
	if err != nil {
		return mapError(err)
	}

	err = memory.StoreUint64(0, uint32(newOffsetPtr), uint64(newOffset))
	if err != nil {
		return errnoFault
	}
	return errnoSuccess
}

func (w *wasiResourceTable) sync(fdIndex int32) int32 {
	fd, ok := w.fds[fdIndex]
	if !ok {
		return errnoBadF
	}
	if err := fd.file.Sync(); err != nil {
		return errnoIO
	}
	return errnoSuccess
}

func (w *wasiResourceTable) tell(
	memory *epsilon.Memory,
	fdIndex, offsetPtr int32,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdTell)
	if errCode != errnoSuccess {
		return errCode
	}

	// Get current position using Seek
	currentOffset, err := fd.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return mapError(err)
	}

	err = memory.StoreUint64(0, uint32(offsetPtr), uint64(currentOffset))
	if err != nil {
		return errnoFault
	}
	return errnoSuccess
}

func (w *wasiResourceTable) write(
	memory *epsilon.Memory,
	fdIndex, ciovecPtr, ciovecLength, nPtr int32,
) int32 {
	fd, errCode := w.getFile(fdIndex, RightsFdWrite)
	if errCode != errnoSuccess {
		return errCode
	}

	return iterCiovec(memory, ciovecPtr, ciovecLength, nPtr, fd.file.Write)
}

func (w *wasiResourceTable) pathCreateDirectory(
	memory *epsilon.Memory,
	fdIndex, pathPtr, pathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathFilestatGet(
	memory *epsilon.Memory,
	fdIndex, flags, pathPtr, pathLen, filestatPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathFilestatSetTimes(
	memory *epsilon.Memory,
	fdIndex, flags, pathPtr, pathLen int32,
	atim, mtim int64,
	fstFlags int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathLink(
	memory *epsilon.Memory,
	oldIndex int32,
	oldFlags, oldPathPtr, oldPathLen, newIndex, newPathPtr, newPathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathOpen(
	memory *epsilon.Memory,
	fdIndex, dirflags, pathPtr, pathLen, oflags int32,
	rightsBase, rightsInheriting int64,
	fdflags, newFdPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathReadlink(
	memory *epsilon.Memory,
	fdIndex, pathPtr, pathLen, bufPtr, bufLen, bufusedPtr int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathRemoveDirectory(
	memory *epsilon.Memory,
	fdIndex, pathPtr, pathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathRename(
	memory *epsilon.Memory,
	fdIndex, oldPathPtr, oldPathLen, newFdIndex, newPathPtr, newPathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathSymlink(
	memory *epsilon.Memory,
	targetPathPtr, targetPathLen, fdIndex, linkPathPtr, linkPathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) pathUnlinkFile(
	memory *epsilon.Memory,
	fdIndex, pathPtr, pathLen int32,
) int32 {
	panic("not implemented")
}

func (w *wasiResourceTable) allocateFdIndex() (int32, error) {
	if len(w.fds) >= maxFileDescriptors {
		return 0, errMaxFileDescriptorsReached
	}

	// Find next available fd starting from 3
	for fd := int32(3); ; fd++ {
		if _, exists := w.fds[fd]; !exists {
			return fd, nil
		}
	}
}

// allocateFd allocates a new file descriptor and returns its index and an error
// code.
func (w *wasiResourceTable) allocateFd(
	file *os.File,
	rights, inheritRights int64,
	flags uint16,
) (int32, int32) {
	fd, err := newFileDescriptor(file, rights, inheritRights, flags)
	if err != nil {
		file.Close()
		return 0, mapError(err)
	}
	newFdIndex, err := w.allocateFdIndex()
	if err != nil {
		fd.close()
		return 0, mapError(err)
	}
	w.fds[newFdIndex] = fd
	return newFdIndex, errnoSuccess
}

func (w *wasiResourceTable) getFile(
	fdIdx int32,
	rights int64,
) (*wasiFileDescriptor, int32) {
	fd, errCode := w.getFileOrDir(fdIdx, rights)
	if errCode != errnoSuccess {
		return nil, errCode
	}
	if fd.fileType == fileTypeDirectory {
		return nil, errnoIsDir
	}
	return fd, errnoSuccess
}

func (w *wasiResourceTable) getDir(
	fdIdx int32,
	rights int64,
) (*wasiFileDescriptor, int32) {
	fd, errCode := w.getFileOrDir(fdIdx, rights)
	if errCode != errnoSuccess {
		return nil, errCode
	}
	if fd.fileType != fileTypeDirectory {
		return nil, errnoNotDir
	}
	return fd, errnoSuccess
}

func (w *wasiResourceTable) getFileOrDir(
	fdIdx int32,
	rights int64,
) (*wasiFileDescriptor, int32) {
	fd, ok := w.fds[fdIdx]
	if !ok {
		return nil, errnoBadF
	}
	if fd.rights&rights == 0 {
		return nil, errnoNotCapable
	}
	if fd.fileType == fileTypeDirectory {
		return nil, errnoBadF
	}
	return fd, errnoSuccess
}

// iterIovec reads data from the given iovec items and stores it in memory.
// Returns an error code.
func iterIovec(
	memory *epsilon.Memory,
	iovecPtr, iovecLength, totalReadPtr int32,
	readBytes func([]byte, int64) (int, error),
) int32 {
	var totalRead uint32
	for i := range iovecLength {
		iovec, err := memory.Get(0, uint32(iovecPtr)+uint32(i*8), 8)
		if err != nil {
			return errnoFault
		}

		ptr := binary.LittleEndian.Uint32(iovec[0:4])
		length := binary.LittleEndian.Uint32(iovec[4:8])

		buf := make([]byte, length)
		n, err := readBytes(buf, int64(totalRead))
		if err != nil && err != io.EOF {
			return mapError(err)
		}

		if err := memory.Set(0, ptr, buf[:n]); err != nil {
			return errnoFault
		}

		totalRead += uint32(n)
		if n < int(length) {
			break
		}
	}
	if err := memory.StoreUint32(0, uint32(totalReadPtr), totalRead); err != nil {
		return errnoFault
	}
	return errnoSuccess
}

// iterCiovec writes data from the given ciovec items using the given writeBytes
// function. Returns an error code.
func iterCiovec(
	memory *epsilon.Memory,
	ciovecPtr, ciovecLength, totalWrittenPtr int32,
	writeBytes func([]byte) (int, error),
) int32 {
	var totalWritten uint32
	for i := range ciovecLength {
		ciovec, err := memory.Get(0, uint32(ciovecPtr)+uint32(i*8), 8)
		if err != nil {
			return errnoFault
		}

		ptr := binary.LittleEndian.Uint32(ciovec[0:4])
		length := binary.LittleEndian.Uint32(ciovec[4:8])

		data, err := memory.Get(0, ptr, length)
		if err != nil {
			return errnoFault
		}

		n, err := writeBytes(data)
		totalWritten += uint32(n)

		if err != nil {
			if totalWritten > 0 {
				break
			}
			return mapError(err)
		}

		if n < len(data) {
			break
		}
	}

	err := memory.StoreUint32(0, uint32(totalWrittenPtr), totalWritten)
	if err != nil {
		return errnoFault
	}
	return errnoSuccess
}

func getModeFileType(mode os.FileMode) uint8 {
	switch {
	case mode.IsDir():
		return fileTypeDirectory
	case mode.IsRegular():
		return fileTypeRegularFile
	case mode&os.ModeSymlink != 0:
		return fileTypeSymbolicLink
	case mode&os.ModeSocket != 0:
		return fileTypeSocketStream
	case mode&os.ModeNamedPipe != 0:
		return fileTypeCharacterDevice
	case mode&os.ModeCharDevice != 0:
		return fileTypeCharacterDevice
	case mode&os.ModeDevice != 0:
		return fileTypeBlockDevice
	default:
		return fileTypeUnknown
	}
}

func (w *wasiResourceTable) readString(
	memory *epsilon.Memory,
	ptr, length int32,
) (string, error) {
	oldPathBytes, err := memory.Get(0, uint32(ptr), uint32(length))
	if err != nil {
		return "", err
	}
	return string(oldPathBytes), nil
}

func mapError(err error) int32 {
	if err == nil {
		return errnoSuccess
	}

	if err == errMaxFileDescriptorsReached {
		return errnoNFile
	}

	// Unpack os.PathError/LinkError
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	if le, ok := err.(*os.LinkError); ok {
		err = le.Err
	}
	if se, ok := err.(*os.SyscallError); ok {
		err = se.Err
	}

	// Check specific errors
	if err == os.ErrNotExist {
		return errnoNoEnt
	}
	if err == os.ErrExist {
		return errnoExist
	}
	if err == os.ErrPermission {
		return errnoAcces
	}

	// Check syscall errno
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.EACCES:
			return errnoAcces
		case syscall.EPERM:
			return errnoPerm
		case syscall.ENOENT:
			return errnoNoEnt
		case syscall.EEXIST:
			return errnoExist
		case syscall.EISDIR:
			return errnoIsDir
		case syscall.ENOTDIR:
			return errnoNotDir
		case syscall.EINVAL:
			return errnoInval
		case syscall.ENOTEMPTY:
			return errnoNotEmpty
		case syscall.ELOOP:
			return errnoLoop
		case syscall.EBADF:
			return errnoBadF
		case syscall.EMFILE, syscall.ENFILE:
			return errnoNFile
		case syscall.ENAMETOOLONG:
			return errnoNameTooLong
		case syscall.EPIPE:
			return errnoPipe
		}
	}

	// Fallback
	return errnoNotCapable
}
