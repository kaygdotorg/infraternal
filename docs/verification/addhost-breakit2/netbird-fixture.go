// Runs the real NetBird SSH server with a generated memory-held host key and an isolated synthetic peer policy (#169).
// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/ssh/server"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func main() {
	// No management daemon, actual peer or JWT is used. Only this owned target's
	// SSH execution implementation is real; its network authorization is a fixture.
	log.SetOutput(io.Discard)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("fixture key generation failed")
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		panic("fixture key encoding failed")
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		panic("fixture public key encoding failed")
	}
	s := server.New(&server.Config{HostKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})})
	// Accept only this Docker bridge's gateway client, never other containers.
	s.SetNetworkValidation(wgaddr.Address{IP: netip.MustParseAddr(os.Args[1]), Network: netip.PrefixFrom(netip.MustParseAddr(os.Args[2]), 32)})
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := s.Start(ctx, netip.MustParseAddrPort("0.0.0.0:22")); err != nil {
		panic("fixture listener failed")
	}
	defer s.Stop()
	if err := os.MkdirAll("/run/addhost-breakit2", 0755); err != nil {
		panic("fixture receipt directory failed")
	}
	if err := os.WriteFile("/run/addhost-breakit2/sshd.pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		panic("fixture pid receipt failed")
	}
	fmt.Print(string(ssh.MarshalAuthorizedKey(key)))
	<-ctx.Done()
}
