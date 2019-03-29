// +build !windows

package du

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

//DiskUsage is an object holding a disk usage
type DiskUsage struct {
	stat *unix.Statfs_t
}

// NewDiskUsage returns an object holding the disk usage of volumePath assuming volumePath is a valid path
func NewDiskUsage(volumePath string) (*DiskUsage, error) {
	var stat unix.Statfs_t
	ch := make(chan error)
	go func() {
		// The closure does a non-blocking send, which it achieves by using the send operation in select statement with a default case.
		// If the send cannot go through immediately the default case will be selected (https://blog.golang.org/go-concurrency-patterns-timing-out-and).
		select {
		case ch <- unix.Statfs(volumePath, &stat):
		default:
		}
	}()
	select {
	case err := <-ch:
		return &DiskUsage{&stat}, err
	case <-time.After(5 * time.Second):
		return &DiskUsage{&stat}, errors.New("timeout getting disk usage")
	}
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
