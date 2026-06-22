//go:build windows
//go:generate go run github.com/akavel/rsrc@latest -manifest main.exe.manifest -o rsrc.syso

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/lxn/walk"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/gui"
	"github.com/TenHopesForOneSolution/check-with-virustotal/internal/install"
)

func main() {
	args := os.Args[1:]

	// Launch settings when run from the Start Menu shortcut or without arguments.
	if len(args) == 0 {
		gui.ShowSettings()
		return
	}

	switch strings.ToLower(args[0]) {
	case "--install", "/install":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := install.Install(exe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Context menu item and Start Menu shortcut installed.")
	case "--uninstall", "/uninstall":
		if err := install.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Context menu item and Start Menu shortcut removed.")
	default:
		// The first argument is treated as the file path selected from the context menu.
		path := strings.Trim(args[0], `"`)
		if _, err := os.Stat(path); err != nil {
			walk.MsgBox(nil, "Error", "File not found: "+path, walk.MsgBoxIconError)
			os.Exit(1)
		}
		gui.ShowScan(path)
	}
}
