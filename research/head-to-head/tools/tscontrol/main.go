// SPDX-License-Identifier: AGPL-3.0-only

// Command tscontrol is the head-to-head kit's local Tailscale coordination
// stack: Tailscale's own test control server (tstest/integration/testcontrol),
// one DERP relay and one STUN responder, all bound to a private test address.
//
// It exists so that unmodified, officially released tailscaled/tailscale
// binaries can join a two-node tailnet with no account and no traffic leaving
// the benchmark namespaces. It is built from the same Tailscale release tag as
// the client binaries, so the control protocol matches. Nothing here is part
// of infraternal; it is measurement scaffolding only.
//
// Invariants: every listener binds the address given by -addr; the process
// prints one "ready <control-url>" line on stdout once all three services
// accept connections, and exits when stdin closes, so its parent owns its
// lifetime without signals.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

func main() {
	addr := flag.String("addr", "127.0.0.1", "IPv4 address every service binds")
	controlPort := flag.Int("control-port", 9911, "control server TCP port")
	verbose := flag.Bool("v", false, "log control and relay activity to stderr")
	flag.Parse()

	logf := func(string, ...any) {}
	if *verbose {
		logf = log.Printf
	}

	// DERP over TLS with a throwaway certificate; the DERP map marks the node
	// InsecureForTests so clients skip verification, as Tailscale's own
	// integration tests do.
	derp := derpserver.New(key.NewNode(), logf)
	derpListener, err := net.Listen("tcp", net.JoinHostPort(*addr, "0"))
	check(err)
	derpHTTP := httptest.NewUnstartedServer(derpserver.Handler(derp))
	derpHTTP.Listener.Close()
	derpHTTP.Listener = derpListener
	derpHTTP.Config.ErrorLog = log.New(io.Discard, "", 0)
	derpHTTP.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	derpHTTP.StartTLS()

	stun := stunserver.New(context.Background())
	check(stun.Listen(net.JoinHostPort(*addr, "0")))
	go func() { _ = stun.Serve() }()
	stunPort := stun.LocalAddr().(*net.UDPAddr).Port

	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "h2h",
				RegionName: "head-to-head",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "h2h1",
					RegionID:         1,
					HostName:         *addr,
					IPv4:             *addr,
					IPv6:             "none",
					STUNPort:         stunPort,
					DERPPort:         derpListener.Addr().(*net.TCPAddr).Port,
					InsecureForTests: true,
					STUNTestIP:       *addr,
				}},
			},
		},
	}

	controlURL := fmt.Sprintf("http://%s", net.JoinHostPort(*addr, fmt.Sprint(*controlPort)))
	control := &testcontrol.Server{
		Logf:             logf,
		DERPMap:          derpMap,
		AllNodesSameUser: true,
		ExplicitBaseURL:  controlURL,
	}
	controlListener, err := net.Listen("tcp", net.JoinHostPort(*addr, fmt.Sprint(*controlPort)))
	check(err)
	go func() { _ = http.Serve(controlListener, control) }()

	fmt.Printf("ready %s\n", controlURL)
	// The parent closes stdin to stop the stack.
	_, _ = io.Copy(io.Discard, bufio.NewReader(os.Stdin))
	derpHTTP.Close()
	derp.Close()
	controlListener.Close()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
