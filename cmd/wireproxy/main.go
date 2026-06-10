package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/windtf/wireproxy"
	"golang.zx2c4.com/wireguard/device"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// default paths for wireproxy config file
var default_config_paths = []string{
	"/etc/wireproxy/wireproxy.conf",
	os.Getenv("HOME") + "/.config/wireproxy.conf",
}

var version = "1.0.8-dev"

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

// check if default config file paths exist
func configFilePath() (string, bool) {
	for _, path := range default_config_paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}


func main() {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-s
		cancel()
	}()

	exePath := executablePath()
	lock("boot")

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		lock("boot-daemon")
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}
	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")

	config := parser.String("c", "config", &argparse.Options{Help: "Path of configuration file"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	if *printVerison {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	if *config == "" {
		if path, config_exist := configFilePath(); config_exist {
			*config = path
		} else {
			fmt.Println("configuration path is required")
			return
		}
	}

	if !*daemon {
		lock("read-config")
	}

	conf, err := wireproxy.ParseConfig(*config)
	if err != nil {
		log.Fatal(err)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	lockNetwork(conf.Routines, info)

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	// Wireguard doesn't allow configuring which FD to use for logging
	// https://github.com/WireGuard/wireguard-go/blob/master/device/logger.go#L39
	// so redirect STDOUT to STDERR, we don't want to print anything to STDOUT anyways
	os.Stdout = os.Stderr
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	lock("ready")

	tun, err := wireproxy.StartWireguard(conf, logLevel)
	if err != nil {
		log.Fatal(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
	}

	tun.StartPingIPs()

	if *info != "" {
		go func() {
			err := http.ListenAndServe(*info, tun)
			if err != nil {
				panic(err)
			}
		}()
	}

	<-ctx.Done()
}
