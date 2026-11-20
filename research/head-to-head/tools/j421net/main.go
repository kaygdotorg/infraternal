// SPDX-License-Identifier: AGPL-3.0-only
// Command j421net is the macOS measurement tool of the head-to-head kit (#260; measurement only,
// never linked into the product). Versioned here from J674 on; before that it lived only on the Mac VM.
//
// macOS has no network namespaces, so both WireGuard endpoints run on one host. Every socket
// this tool opens can be bound to a tunnel interface with IP_BOUND_IF; XNU's scoped routing then
// sends traffic between the two tunnel addresses through utun instead of delivering it over lo0.
// The runner proves that with the engines' own byte counters.
//
// Subcommands (one JSON object on stdout each, except the servers):
//
//	keys                                   two X25519 key pairs as hex JSON
//	uapi SOCK                              send the UAPI request on stdin, print the reply
//	sink   -bind A:P [-if I]               TCP sink; on EOF it returns its per-100ms byte buckets
//	source -to A:P [-if I] -flows N -secs S  N TCP flows for S seconds; goodput, stalls, 0-byte flows
//	echo   -bind A:P [-if I]               UDP echo server
//	probe  -to A:P [-if I] -count N -interval-ms M  UDP RTT probes; received and loss-aware percentiles
//
// Goodput is counted at the receiver: the sink reports what it read, bucketed per 100 ms from
// the first byte, and the source divides the sum by the time from the first dial to the last
// sink reply. A stall is a whole second in which the receiver read 0 bytes summed over all flows.
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ipBoundIf is IP_BOUND_IF from Darwin's <netinet/in.h>.
const ipBoundIf = 25

// bucket is the receiver's sampling period for stall detection.
const bucket = 100 * time.Millisecond

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: j421net keys|uapi|sink|source|echo|probe ...")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "keys":
		keys()
	case "uapi":
		uapi(args)
	case "sink":
		sink(args)
	case "source":
		source(args)
	case "echo":
		echo(args)
	case "probe":
		probe(args)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand", cmd)
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "j421net:", err)
		os.Exit(1)
	}
}

func emit(v any) {
	b, err := json.Marshal(v)
	must(err)
	fmt.Println(string(b))
}

// keys prints two fresh X25519 key pairs (a, b) as hex, the form UAPI expects.
func keys() {
	out := map[string]string{}
	for _, n := range []string{"a", "b"} {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		must(err)
		out[n+"_private"] = hex.EncodeToString(k.Bytes())
		out[n+"_public"] = hex.EncodeToString(k.PublicKey().Bytes())
	}
	emit(out)
}

// uapi sends stdin to a WireGuard UAPI socket and prints the reply; it exits 1 unless errno=0.
func uapi(args []string) {
	must(checkArgs(args, 1))
	c, err := net.DialTimeout("unix", args[0], 10*time.Second)
	must(err)
	req, err := io.ReadAll(os.Stdin)
	must(err)
	_, err = c.Write(req)
	must(err)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	var reply strings.Builder
	for {
		line, err := r.ReadString('\n')
		reply.WriteString(line)
		if err != nil || line == "\n" {
			break
		}
	}
	os.Stdout.WriteString(reply.String())
	if !strings.Contains(reply.String(), "errno=0") {
		os.Exit(1)
	}
}

func checkArgs(a []string, n int) error {
	if len(a) != n {
		return fmt.Errorf("want %d arguments, got %d", n, len(a))
	}
	return nil
}

// boundControl returns a socket Control hook that pins the socket to ifname (none if empty).
func boundControl(ifname string) func(string, string, syscall.RawConn) error {
	if ifname == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(ifname)
	must(err)
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifi.Index)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// sink reads each TCP connection to EOF, then writes back its per-100ms byte buckets as one
// JSON line and closes. Buckets start at the connection's accept time.
func sink(args []string) {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	bind := fs.String("bind", "", "address:port")
	ifn := fs.String("if", "", "interface to bind to")
	must(fs.Parse(args))
	lc := net.ListenConfig{Control: boundControl(*ifn)}
	ln, err := lc.Listen(context.Background(), "tcp4", *bind)
	must(err)
	for {
		c, err := ln.Accept()
		must(err)
		go func(c net.Conn) {
			defer c.Close()
			t0 := time.Now()
			buckets := []int64{}
			buf := make([]byte, 1<<20)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					i := int(time.Since(t0) / bucket)
					for len(buckets) <= i {
						buckets = append(buckets, 0)
					}
					buckets[i] += int64(n)
				}
				if err != nil {
					break
				}
			}
			b, _ := json.Marshal(map[string]any{"buckets": buckets})
			_, _ = c.Write(append(b, '\n'))
		}(c)
	}
}

// flowResult is one flow's outcome as seen by the source.
type flowResult struct {
	Bytes   int64   `json:"bytes"`
	Buckets []int64 `json:"-"`
	Err     string  `json:"err,omitempty"`
	Start   float64 `json:"start_s"`
}

// source opens N flows at once, writes for S seconds, half-closes, and waits for each sink's
// bucket reply (bounded by a drain timeout so a stuck tunnel is reported, not hung on).
func source(args []string) {
	fs := flag.NewFlagSet("source", flag.ExitOnError)
	to := fs.String("to", "", "address:port")
	ifn := fs.String("if", "", "interface to bind to")
	flows := fs.Int("flows", 1, "parallel TCP flows")
	secs := fs.Float64("secs", 10, "seconds of writing")
	drain := fs.Float64("drain", 30, "seconds to wait for delivery after writing stops")
	must(fs.Parse(args))
	d := net.Dialer{Control: boundControl(*ifn), Timeout: 10 * time.Second}
	block := make([]byte, 256<<10)
	_, _ = rand.Read(block)
	res := make([]flowResult, *flows)
	var wg sync.WaitGroup
	t0 := time.Now()
	stop := t0.Add(time.Duration(*secs * float64(time.Second)))
	for i := range res {
		wg.Add(1)
		go func(r *flowResult) {
			defer wg.Done()
			c, err := d.Dial("tcp4", *to)
			if err != nil {
				r.Err = err.Error()
				return
			}
			defer c.Close()
			r.Start = time.Since(t0).Seconds()
			for time.Now().Before(stop) {
				_ = c.SetWriteDeadline(stop)
				if _, err := c.Write(block); err != nil && !isTimeout(err) {
					r.Err = err.Error()
					return
				}
			}
			_ = c.(*net.TCPConn).CloseWrite()
			_ = c.SetReadDeadline(stop.Add(time.Duration(*drain * float64(time.Second))))
			line, err := bufio.NewReader(c).ReadBytes('\n')
			if err != nil {
				r.Err = "no sink reply: " + err.Error()
				return
			}
			var rep struct{ Buckets []int64 }
			if err := json.Unmarshal(line, &rep); err != nil {
				r.Err = err.Error()
				return
			}
			r.Buckets = rep.Buckets
			for _, b := range rep.Buckets {
				r.Bytes += b
			}
		}(&res[i])
	}
	wg.Wait()
	elapsed := time.Since(t0).Seconds()
	var total int64
	zero := 0
	errs := 0
	maxLen := 0
	for _, r := range res {
		total += r.Bytes
		if r.Bytes == 0 {
			zero++
		}
		if r.Err != "" {
			errs++
		}
		if len(r.Buckets) > maxLen {
			maxLen = len(r.Buckets)
		}
	}
	// Per-second receiver totals over the writing window only (flows start within ms of each
	// other, so the per-flow accept-time origin is close enough for 1 s resolution).
	perBucket := make([]int64, maxLen)
	for _, r := range res {
		for i, b := range r.Buckets {
			perBucket[i] += b
		}
	}
	window := int(*secs)
	perSec := make([]float64, 0, window)
	stalls := 0
	for s := 0; s < window; s++ {
		var sum int64
		for i := s * 10; i < (s+1)*10 && i < len(perBucket); i++ {
			sum += perBucket[i]
		}
		perSec = append(perSec, round3(float64(sum)*8/1e9))
		if sum == 0 {
			stalls++
		}
	}
	emit(map[string]any{
		"flows": *flows, "secs": *secs, "elapsed_s": round3(elapsed), "bytes": total,
		"gbit_per_s": round3(float64(total) * 8 / elapsed / 1e9), "zero_byte_flows": zero,
		"flow_errors": errs, "stall_seconds": stalls, "per_second_gbit": perSec, "per_flow": res,
	})
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// echo returns every UDP datagram to its sender.
func echo(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	bind := fs.String("bind", "", "address:port")
	ifn := fs.String("if", "", "interface to bind to")
	must(fs.Parse(args))
	lc := net.ListenConfig{Control: boundControl(*ifn)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", *bind)
	must(err)
	buf := make([]byte, 65536)
	for {
		n, src, err := pc.ReadFrom(buf)
		must(err)
		_, _ = pc.WriteTo(buf[:n], src)
	}
}

// probe sends COUNT sequenced UDP probes, one every INTERVAL, and reports RTT percentiles.
// Loss-aware percentiles (D331) count a lost probe as an infinite RTT; null means infinite.
func probe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	to := fs.String("to", "", "address:port")
	ifn := fs.String("if", "", "interface to bind to")
	count := fs.Int("count", 1000, "probes")
	interval := fs.Float64("interval-ms", 5, "milliseconds between probes")
	wait := fs.Float64("wait-s", 3, "seconds to wait for late replies")
	raw := fs.String("raw", "", "file for raw RTTs (ms, -1 = lost), one per line")
	must(fs.Parse(args))
	d := net.Dialer{Control: boundControl(*ifn)}
	c, err := d.Dial("udp4", *to)
	must(err)
	rtt := make([]float64, *count)
	for i := range rtt {
		rtt[i] = -1
	}
	base := time.Now()
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				if isTimeout(err) {
					close(done)
					return
				}
				continue // ECONNREFUSED before the echo is up, and the like
			}
			now := time.Since(base)
			if n < 12 {
				continue
			}
			seq := binary.LittleEndian.Uint32(buf)
			sent := time.Duration(binary.LittleEndian.Uint64(buf[4:]))
			mu.Lock()
			if int(seq) < len(rtt) && rtt[seq] < 0 {
				rtt[seq] = float64(now-sent) / 1e6
			}
			mu.Unlock()
		}
	}()
	pkt := make([]byte, 64)
	step := time.Duration(*interval * float64(time.Millisecond))
	for i := 0; i < *count; i++ {
		due := base.Add(time.Duration(i) * step)
		if w := time.Until(due); w > 0 {
			time.Sleep(w)
		}
		binary.LittleEndian.PutUint32(pkt, uint32(i))
		binary.LittleEndian.PutUint64(pkt[4:], uint64(time.Since(base)))
		_, _ = c.Write(pkt)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(*wait * float64(time.Second))))
	<-done
	mu.Lock()
	defer mu.Unlock()
	if *raw != "" {
		f, err := os.Create(*raw)
		must(err)
		w := bufio.NewWriter(f)
		for _, v := range rtt {
			fmt.Fprintf(w, "%.3f\n", v)
		}
		must(w.Flush())
		must(f.Close())
	}
	got := []float64{}
	for _, v := range rtt {
		if v >= 0 {
			got = append(got, v)
		}
	}
	sort.Float64s(got)
	lost := *count - len(got)
	q := func(s []float64, n int, p float64) any { // nearest-rank over n samples, beyond s = inf
		k := int(math.Ceil(p*float64(n))) - 1
		if k < 0 {
			k = 0
		}
		if k >= len(s) {
			return nil
		}
		return round3(s[k])
	}
	out := map[string]any{"sent": *count, "received": len(got), "lost": lost,
		"loss_aware_p50_ms": q(got, *count, .50), "loss_aware_p99_ms": q(got, *count, .99)}
	if len(got) > 0 {
		out["p50_ms"] = q(got, len(got), .50)
		out["p99_ms"] = q(got, len(got), .99)
		out["max_ms"] = round3(got[len(got)-1])
	}
	emit(out)
}
