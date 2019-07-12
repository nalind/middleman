package main

import (
	"fmt"
	"os"
	"os/exec"
)

// #include <linux/seccomp.h>
// #include <sys/syscall.h>
// #include <unistd.h>
// #include "mm.h"
import "C"

type Emulator interface {
	Getuid() uint32
	Getgid() uint32
}

type emulator struct {
}

func (e emulator) Getuid() uint32 {
	return 1
}

func (e emulator) Getgid() uint32 {
	return 2
}

func main() {
	var emulator emulator
	fd := C.seccomp_install_filter()
	if fd == -1 {
		fmt.Printf("error installing filter")
		return
	}
	go func() {
		user := C.seccomp_user_notif_recv(fd)
		for user != nil {
			switch user.notif.data.nr {
			case C.SYS_getuid:
				user.resp.val = C.longlong(emulator.Getuid())
			case C.SYS_getgid:
				user.resp.val = C.longlong(emulator.Getgid())
			}
			if C.seccomp_user_notif_valid(user) == 0 {
				if ret := C.seccomp_user_notif_send(fd, user); ret != 0 {
					fmt.Printf("error %v sending a response", ret)
					C.close(fd)
					return
				}
			}
			user = C.seccomp_user_notif_recv(fd)
		}
	}()
	id := exec.Command("id")
	id.Stdin = os.Stdin
	id.Stdout = os.Stdout
	id.Stderr = os.Stderr
	id.Run()
}
