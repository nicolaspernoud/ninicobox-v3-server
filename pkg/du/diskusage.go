// +build !windows

package du

import (
	"syscall"
)

//DiskUsage is an object holding a disk usage
type DiskUsage struct {
	stat *syscall.Statfs_t
}

// NewDiskUsage returns an object holding the disk usage of volumePath assuming volumePath is a valid path
func NewDiskUsage(volumePath string) (*DiskUsage, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(volumePath, &stat)
	if err != nil {
		return &DiskUsage{}, err
	}
	return &DiskUsage{&stat}, nil
}

// Free returns the total free bytes on file system
func (du *DiskUsage) Free() uint64 {
	return du.stat.Bfree * uint64(du.stat.Bsize)
}

// Available returns available bytes on file system to an unpriveleged user
func (du *DiskUsage) Available() uint64 {
	return du.stat.Bavail * uint64(du.stat.Bsize)
}

// Size returns the total size of the file system
func (du *DiskUsage) Size() uint64 {
	return du.stat.Blocks * uint64(du.stat.Bsize)
}

// Used returns the total bytes used in file system
func (du *DiskUsage) Used() uint64 {
	return du.Size() - du.Free()
}

// Usage returns the percentage of use on the file system
func (du *DiskUsage) Usage() float32 {
	return float32(du.Used()) / float32(du.Size())
}
