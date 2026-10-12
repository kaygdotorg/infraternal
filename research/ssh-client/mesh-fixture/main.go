// SPDX-License-Identifier: AGPL-3.0-only
// Package main runs a loopback-only SSH oracle with network identity (none) authentication.
// Its server engine and configuration match NetBird v0.79.0; synthetic keys stay in memory.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"

	"github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

func main() {
	root := os.Args[1]
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	public := fmt.Sprintf("[127.0.0.1]:%d %s", port, cryptossh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := os.WriteFile(root+"/known_hosts", []byte(public), 0600); err != nil {
		panic(err)
	}
	var connections atomic.Int32
	server := &ssh.Server{
		Version:     "NetBird-SSH-Server-0.79.0",
		HostSigners: []ssh.Signer{signer},
		ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
			count := connections.Add(1)
			if err := os.WriteFile(root+"/connections", []byte(fmt.Sprint(count)), 0600); err != nil {
				panic(err)
			}
			return conn
		},
		Handler: func(session ssh.Session) {
			// Execute read-only test commands with a disposable HOME, never the owner's fixtures.
			command := exec.Command("/bin/sh", "-c", session.RawCommand())
			command.Env = append(os.Environ(), "HOME="+root)
			command.Stdin = session
			command.Stdout = session
			command.Stderr = session.Stderr()
			err := command.Run()
			status := 0
			if err != nil {
				status = 1
			}
			session.Exit(status)
		},
	}
	fmt.Printf("%d\n", port)
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
