package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	stateDir := os.Getenv("ZTNA_STATE_DIR")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "resolve home dir:", err)
			os.Exit(1)
		}
		stateDir = home + "/.ztna"
	}

	switch os.Args[1] {
	case "enroll":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: ztnactl enroll <ctrl_addr> <ca_cert_path> <token>")
			os.Exit(1)
		}
		if err := cmdEnroll(stateDir, os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, "enroll:", err)
			os.Exit(1)
		}
		fmt.Println("enrolled")
	case "login":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: ztnactl login <ctrl_addr>")
			os.Exit(1)
		}
		if err := cmdLogin(stateDir, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "login:", err)
			os.Exit(1)
		}
		fmt.Println("logged in")
	case "connect":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: ztnactl connect <gw_addr> <resource>")
			os.Exit(1)
		}
		if err := cmdConnect(stateDir, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "connect:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  ztnactl enroll <ctrl_addr> <ca_cert_path> <token>
  ztnactl login <ctrl_addr>
  ztnactl connect <gw_addr> <resource>`)
}
