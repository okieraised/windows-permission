package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func main() {
	file := "/Users/TriPham/Desktop/test_flatten.py"
	info, _ := os.Stat(file)

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	UID := strconv.Itoa(int(stat.Uid))
	GID := strconv.Itoa(int(stat.Gid))
	mode := info.Mode().String() // permission

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

}
