//go:build !android

package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/windtf/wireproxy"
	"suah.dev/protect"
)

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	panicIfError(protect.Pledge(promises))
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	panicIfError(protect.Unveil(path, flags))
}

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	return uint16(port)
}

func lock(stage string) {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		unveilOrPanic("/", "r")
		unveilOrPanic(exePath, "x")
		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		pledgeOrPanic("stdio rpath inet dns proc exec")
		// Linux
		panicIfError(landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
		))
	case "boot-daemon":
	case "read-config":
		// OpenBSD
		pledgeOrPanic("stdio rpath inet dns")
	case "ready":
		// no file access is allowed from now on, only networking
		// OpenBSD
		pledgeOrPanic("stdio inet dns")
		// Linux
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies
		panicIfError(landlock.V1.BestEffort().RestrictPaths(
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		))
	default:
		panic("invalid stage")
	}
}

func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxy.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxy.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxy.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	panicIfError(landlock.V4.BestEffort().RestrictNet(rules...))
}
