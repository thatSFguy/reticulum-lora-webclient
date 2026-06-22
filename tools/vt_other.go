//go:build !windows

// Non-Windows terminals (Linux, macOS) handle ANSI escapes and UTF-8 out
// of the box, so there is nothing to enable.

package main

func enableVT() {}
