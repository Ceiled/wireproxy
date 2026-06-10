//go:build android

package main

// Android's seccomp filter blocks Landlock syscalls (SIGSYS).
// Skip all sandboxing on Android — the app sandbox provides isolation.

import "github.com/windtf/wireproxy"

func lock(stage string)                                                {}
func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {}
