package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

const (
	IN_CREATE      = 0x100
	IN_DELETE      = 0x200
	IN_DELETE_SELF = 0x400
	IN_MODIFY      = 0x2
	IN_MOVE        = 0xc0
	IN_MOVED_FROM  = 0x40
	IN_MOVED_TO    = 0x80
	IN_MOVE_SELF   = 0x800
	IN_ATTRIB      = 0x4
)

type timeTest struct {
	timestamp time.Time
}

func main() {
	file := "/Users/TriPham/Desktop/sign_pdf"
	info, _ := os.Stat(file)

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	UID := strconv.Itoa(int(stat.Uid))
	GID := strconv.Itoa(int(stat.Gid))
	mode := info.Mode().String()
	x := info.Mode().Perm() // permission
	size := info.Size()

	owner, err := user.LookupId(UID)
	if err != nil {
		return
	}
	group, err := user.LookupGroupId(GID)
	if err != nil {
		return
	}
	fmt.Println(UID, GID, mode)
	fmt.Println(owner.Name, group.Name)
	fmt.Println(x)
	fmt.Println(size / 1024 / 1024)

	m := timeTest{}
	m.timestamp = time.Now()

	fmt.Println(m.timestamp)

}
