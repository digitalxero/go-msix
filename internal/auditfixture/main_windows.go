// auditfixture is a native shortcut and SCM service acceptance executable.
package main

import (
	"net/url"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var stop = make(chan struct{}, 1)
var statusHandle uintptr
var setStatus = syscall.NewLazyDLL("advapi32.dll").NewProc("SetServiceStatus")

type serviceStatus struct{ kind, state, accepted, win32Exit, serviceExit, checkpoint, waitHint uint32 }

func report(state, accepted uint32) {
	s := serviceStatus{kind: 0x10, state: state, accepted: accepted}
	setStatus.Call(statusHandle, uintptr(unsafe.Pointer(&s)))
}
func serviceMain(argc uint32, argv **uint16) uintptr {
	name := *argv
	handler := syscall.NewCallback(func(control, event uint32, data, ctx uintptr) uintptr {
		if control == 1 {
			select {
			case stop <- struct{}{}:
			default:
			}
		}
		return 0
	})
	h, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("RegisterServiceCtrlHandlerExW").Call(uintptr(unsafe.Pointer(name)), handler, 0)
	statusHandle = h
	if h == 0 {
		return 0
	}
	report(4, 1)
	<-stop
	report(1, 0)
	return 0
}
func main() {
	if len(os.Args) >= 3 && os.Args[1] == "--audit-output" {
		if err := os.WriteFile(os.Args[2], []byte(strings.Join(os.Args[3:], "|")), 0600); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		u, err := url.Parse(os.Args[1])
		if err == nil && strings.HasPrefix(u.Scheme, "gomsix-audit") {
			if err := os.WriteFile(u.Query().Get("out"), []byte("protocol"), 0600); err != nil {
				os.Exit(1)
			}
			return
		}
	}

	name, _ := syscall.UTF16PtrFromString("")
	table := [2]struct {
		name *uint16
		proc uintptr
	}{{name, syscall.NewCallback(serviceMain)}, {nil, 0}}
	result, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("StartServiceCtrlDispatcherW").Call(uintptr(unsafe.Pointer(&table[0])))
	if result == 0 {
		os.Exit(1)
	}
}
