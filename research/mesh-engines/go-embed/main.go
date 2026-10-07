// Package main exposes the Go WireGuard device through a small C ABI for a Rust binary-size measurement.
package main

// SPDX-License-Identifier: AGPL-3.0-only

/*
#include <stdint.h>
*/
import "C"

import (
	"runtime/cgo"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

//export WgCreateDevice
func WgCreateDevice(name *C.char, mtu C.int) C.uintptr_t {
	tunDevice, err := tun.CreateTUN(C.GoString(name), int(mtu))
	if err != nil {
		return 0
	}
	engine := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	return C.uintptr_t(cgo.NewHandle(engine))
}

//export WgCloseDevice
func WgCloseDevice(handle C.uintptr_t) {
	if handle == 0 {
		return
	}
	engine := cgo.Handle(handle).Value().(*device.Device)
	engine.Close()
	cgo.Handle(handle).Delete()
}

func main() {}
