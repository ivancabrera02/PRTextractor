package main

import "syscall"

func syscall3(addr, a0, a1, a2, a3 uintptr) (uintptr, uintptr, error) {
	r0, r1, err := syscall.Syscall6(
		addr,
		4, // número de argumentos
		a0, a1, a2, a3,
		0, 0,
	)
	return r0, r1, err
}
