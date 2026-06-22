//go:build windows

// Windows console setup for the live status display. Classic conhost
// leaves ANSI escape processing OFF for legacy apps and may use a
// non-UTF-8 output codepage, which would turn our escape sequences and
// box-drawing characters into garbage. Enable both at startup. Uses only
// the stdlib syscall package (no cgo, no extra modules) so the
// CGO_ENABLED=0 cross-compile is preserved.

package main

import (
	"syscall"
	"unsafe"
)

func enableVT() {
	const (
		enableVTProcessing = 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
		cpUTF8             = 65001
	)
	k := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := k.NewProc("GetConsoleMode")
	setConsoleMode := k.NewProc("SetConsoleMode")
	setConsoleOutputCP := k.NewProc("SetConsoleOutputCP")

	if h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil {
		var mode uint32
		if r, _, _ := getConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r != 0 {
			setConsoleMode.Call(uintptr(h), uintptr(mode|enableVTProcessing))
		}
	}
	setConsoleOutputCP.Call(uintptr(cpUTF8))
}
