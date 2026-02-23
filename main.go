// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Darren P Meyer
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	exitUp            = 0
	exitNameLookup    = 1
	exitHostUnreach   = 2
	exitInvalidArgs   = 120
	defaultTimeoutMS  = 200
	defaultDNSService = "53"
	lookupTimeout     = 2 * time.Second
)

var hostnameLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type config struct {
	timeoutMS int
	dnsServer string
	port      int
	forceV4   bool
	forceV6   bool
	verbose   bool
	veryVerb  bool
	target    string
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, code, err := parseArgs(args, stderr)
	log := newVerbosityLogger(stdout, stderr, cfg.verbose, cfg.veryVerb)
	if err != nil {
		log.failf("argument parsing", "%v", err)
		if errors.Is(err, flag.ErrHelp) {
			return log.exit(exitUp)
		}
		if code == 0 {
			code = exitInvalidArgs
		}
		return log.exit(code)
	}

	timeout := time.Duration(cfg.timeoutMS) * time.Millisecond
	hostForCheck := cfg.target
	log.stepf("processing target %q", cfg.target)
	if parsedIP, err := netip.ParseAddr(cfg.target); err != nil {
		log.step("validating hostname")
		if err := validateHostname(cfg.target); err != nil {
			log.failf("hostname validation", "%v", err)
			printUsage(stderr)
			fmt.Fprintf(stderr, "\ninvalid host/IP argument %q: %v\n", cfg.target, err)
			return log.exit(exitInvalidArgs)
		}
		log.okf("hostname validation", "valid hostname")
		log.step("resolving hostname")
		lookupCtx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		defer cancel()
		start := time.Now()
		resolvedHost, err := resolveName(lookupCtx, cfg.target, cfg.dnsServer, cfg.resolutionNetworks())
		if err != nil {
			log.failf("hostname resolution", "%v", err)
			return log.exit(exitNameLookup)
		}
		hostForCheck = resolvedHost
		log.setIP(resolvedHost)
		log.okf("hostname resolution", "%s in %dms", resolvedHost, time.Since(start).Milliseconds())
	} else {
		hostForCheck = parsedIP.String()
		log.setIP(hostForCheck)
		log.okf("input IP", "%s", hostForCheck)
	}

	if cfg.port > 0 {
		log.stepf("tcp probe %s", net.JoinHostPort(hostForCheck, strconv.Itoa(cfg.port)))
		start := time.Now()
		if err := tcpCheck(hostForCheck, cfg.port, timeout); err != nil {
			log.failf("tcp probe", "%v", err)
			return log.exit(exitHostUnreach)
		}
		log.okf("tcp probe", "connected in %dms", time.Since(start).Milliseconds())
		return log.exit(exitUp)
	}

	log.stepf("icmp echo %s", hostForCheck)
	start := time.Now()
	if err := pingCheck(hostForCheck, timeout); err != nil {
		log.failf("icmp echo", "%v", err)
		return log.exit(exitHostUnreach)
	}
	log.okf("icmp echo", "reply in %dms", time.Since(start).Milliseconds())
	return log.exit(exitUp)
}

func parseArgs(args []string, stderr io.Writer) (config, int, error) {
	var cfg config
	fs := flag.NewFlagSet("hostup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }

	fs.IntVar(&cfg.timeoutMS, "t", defaultTimeoutMS, "timeout in milliseconds")
	fs.StringVar(&cfg.dnsServer, "d", "", "DNS server to use for hostname lookup (host[:port], default port 53)")
	fs.IntVar(&cfg.port, "p", 0, "TCP port to probe instead of ping")
	fs.BoolVar(&cfg.forceV4, "4", false, "resolve hostnames to IPv4 only")
	fs.BoolVar(&cfg.forceV6, "6", false, "resolve hostnames to IPv6 only")
	fs.BoolVar(&cfg.verbose, "v", false, "print the IP address used")
	fs.BoolVar(&cfg.veryVerb, "vv", false, "verbose step logging to stderr and print final exit code")

	normalizedArgs := reorderInterspersedArgs(args)
	if err := fs.Parse(normalizedArgs); err != nil {
		if cfg.veryVerb {
			cfg.verbose = true
		}
		if errors.Is(err, flag.ErrHelp) {
			return cfg, exitUp, err
		}
		printUsage(stderr)
		return cfg, exitInvalidArgs, err
	}
	if cfg.veryVerb {
		cfg.verbose = true
	}

	rest := fs.Args()
	if len(rest) != 1 {
		printUsage(stderr)
		return cfg, exitInvalidArgs, errors.New("expected exactly one hostname or IP argument")
	}
	cfg.target = strings.TrimSpace(rest[0])
	if cfg.target == "" {
		printUsage(stderr)
		return cfg, exitInvalidArgs, errors.New("empty hostname or IP argument")
	}
	if cfg.timeoutMS <= 0 {
		printUsage(stderr)
		return cfg, exitInvalidArgs, errors.New("timeout must be > 0")
	}
	if cfg.port < 0 || cfg.port > 65535 {
		printUsage(stderr)
		return cfg, exitInvalidArgs, errors.New("port must be in range 0-65535")
	}
	if cfg.dnsServer != "" {
		if _, err := normalizeDNSAddr(cfg.dnsServer); err != nil {
			printUsage(stderr)
			return cfg, exitInvalidArgs, fmt.Errorf("invalid -d value: %w", err)
		}
	}

	return cfg, 0, nil
}

func reorderInterspersedArgs(args []string) []string {
	if len(args) < 2 {
		return args
	}

	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 2)
	expectValue := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if expectValue {
			flags = append(flags, arg)
			expectValue = false
			continue
		}

		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}

		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}

		flags = append(flags, arg)
		if strings.Contains(arg, "=") {
			continue
		}

		name := strings.TrimLeft(arg, "-")
		switch name {
		case "t", "d", "p":
			expectValue = true
		}
	}

	return append(flags, positionals...)
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "Usage: hostup [options] <hostname-or-ip>")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "Checks whether a host is up using ping (default) or a TCP connect probe.")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "Options:")
	fmt.Fprintln(stderr, "  -t <ms>        Timeout in milliseconds (default 200)")
	fmt.Fprintln(stderr, "  -d <host:port> DNS server for hostname lookups (port defaults to 53)")
	fmt.Fprintln(stderr, "  -p <port>      TCP port to probe instead of ping")
	fmt.Fprintln(stderr, "  -4             Resolve hostnames to IPv4 only")
	fmt.Fprintln(stderr, "  -6             Resolve hostnames to IPv6 only")
	fmt.Fprintln(stderr, "  -v             Print the IP address used (stdout)")
	fmt.Fprintln(stderr, "  -vv            Verbose step logging to stderr, final exit code, and implies -v")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "Exit codes:")
	fmt.Fprintln(stderr, "  0   Host is reachable (ping reply or TCP connect succeeded)")
	fmt.Fprintln(stderr, "  1   Hostname lookup failed")
	fmt.Fprintln(stderr, "  2   Host lookup succeeded but reachability probe failed")
	fmt.Fprintln(stderr, "  120 Invalid arguments (help shown)")
}

type verbosityLogger struct {
	stdout   io.Writer
	stderr   io.Writer
	verbose  bool
	veryVerb bool
	ip       string
	ipShown  bool
}

func newVerbosityLogger(stdout, stderr io.Writer, verbose, veryVerb bool) *verbosityLogger {
	if veryVerb {
		verbose = true
	}
	return &verbosityLogger{
		stdout:   stdout,
		stderr:   stderr,
		verbose:  verbose,
		veryVerb: veryVerb,
	}
}

func (l *verbosityLogger) setIP(ip string) {
	l.ip = ip
}

func (l *verbosityLogger) step(msg string) {
	if l.veryVerb {
		fmt.Fprintf(l.stderr, "%s\n", msg)
	}
}

func (l *verbosityLogger) stepf(format string, args ...any) {
	if l.veryVerb {
		fmt.Fprintf(l.stderr, format+"\n", args...)
	}
}

func (l *verbosityLogger) okf(step, format string, args ...any) {
	if l.veryVerb {
		fmt.Fprintf(l.stderr, "%s: ok", step)
		if format != "" {
			fmt.Fprintf(l.stderr, " (%s)", fmt.Sprintf(format, args...))
		}
		fmt.Fprintln(l.stderr)
	}
}

func (l *verbosityLogger) failf(step, format string, args ...any) {
	if l.veryVerb {
		fmt.Fprintf(l.stderr, "%s: fail", step)
		if format != "" {
			fmt.Fprintf(l.stderr, " (%s)", fmt.Sprintf(format, args...))
		}
		fmt.Fprintln(l.stderr)
	}
}

func (l *verbosityLogger) emitIPIfNeeded() {
	if !l.verbose || l.ipShown || l.ip == "" {
		return
	}
	fmt.Fprintln(l.stdout, l.ip)
	l.ipShown = true
}

func (l *verbosityLogger) exit(code int) int {
	l.emitIPIfNeeded()
	if l.veryVerb {
		fmt.Fprintf(l.stderr, "exit with code %d\n", code)
	}
	return code
}

func (c config) resolutionNetworks() []string {
	switch {
	case c.forceV4 && !c.forceV6:
		return []string{"ip4"}
	case c.forceV6 && !c.forceV4:
		return []string{"ip6"}
	default:
		// Default and (-4 && -6): prefer IPv6, then fall back to IPv4.
		return []string{"ip6", "ip4"}
	}
}

func validateHostname(host string) error {
	if len(host) > 253 {
		return errors.New("hostname too long")
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" {
		return errors.New("hostname is empty")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostnameLabelRE.MatchString(label) {
			return fmt.Errorf("invalid hostname label %q", label)
		}
	}
	return nil
}

func resolveName(ctx context.Context, host, dnsServer string, networks []string) (string, error) {
	resolver := net.DefaultResolver
	if dnsServer != "" {
		addr, err := normalizeDNSAddr(dnsServer)
		if err != nil {
			return "", err
		}
		dialer := &net.Dialer{}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// DNS over TCP/UDP is chosen by the resolver; honor the provided server.
				return dialer.DialContext(ctx, network, addr)
			},
		}
	}

	var firstErr error
	for _, network := range networks {
		ip, err := lookupFirstIP(ctx, resolver, network, host)
		if err == nil {
			return ip, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no lookup families configured")
	}
	return "", firstErr
}

func lookupFirstIP(ctx context.Context, resolver *net.Resolver, network, host string) (string, error) {
	ips, err := resolver.LookupIP(ctx, network, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no %s addresses returned", network)
	}
	return ips[0].String(), nil
}

func normalizeDNSAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty DNS server")
	}

	// Bracketed IPv6 or explicit host:port.
	if strings.Contains(s, "]") || strings.Count(s, ":") == 1 {
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), defaultDNSService), nil
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", err
		}
		if port == "" {
			port = defaultDNSService
		}
		return net.JoinHostPort(host, port), nil
	}

	// Unbracketed IPv6 literal (with no port).
	if ip, err := netip.ParseAddr(s); err == nil && ip.Is6() {
		return net.JoinHostPort(s, defaultDNSService), nil
	}

	// Hostname or IPv4, no port.
	return net.JoinHostPort(s, defaultDNSService), nil
}

func tcpCheck(host string, port int, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func pingCheck(host string, timeout time.Duration) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}

	if addr.Is4() {
		return icmpPing(addr, timeout, false)
	}
	return icmpPing(addr, timeout, true)
}

func icmpPing(addr netip.Addr, timeout time.Duration, isV6 bool) error {
	id, seq := randomEchoIDSeq()
	payload := []byte("hostup")

	var (
		protocol  int
		reqType   icmp.Type
		replyType icmp.Type
		networks  []string
		ipBytes   = net.IP(addr.AsSlice())
	)

	if isV6 {
		protocol = 58
		reqType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		networks = []string{"udp6", "ip6:ipv6-icmp"}
	} else {
		protocol = 1
		reqType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		networks = []string{"udp4", "ip4:icmp"}
	}

	msg := icmp.Message{
		Type: reqType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: payload,
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	var lastErr error
	for _, network := range networks {
		if err := icmpPingOnNetwork(network, protocol, replyType, ipBytes, wb, id, seq, payload, timeout); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func icmpPingOnNetwork(network string, protocol int, replyType icmp.Type, ip net.IP, wb []byte, id, seq int, payload []byte, timeout time.Duration) error {
	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var dst net.Addr
	if strings.HasPrefix(network, "udp") {
		dst = &net.UDPAddr{IP: ip}
	} else {
		dst = &net.IPAddr{IP: ip}
	}
	if _, err := c.WriteTo(wb, dst); err != nil {
		return err
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		rm, err := icmp.ParseMessage(protocol, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != replyType {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// Unprivileged ICMP datagram endpoints may rewrite the echo identifier.
		if strings.HasPrefix(network, "udp") {
			if echo.Seq != seq || !bytes.Equal(echo.Data, payload) {
				continue
			}
		} else if echo.ID != id || echo.Seq != seq || !bytes.Equal(echo.Data, payload) {
			continue
		}
		return nil
	}
}

func randomEchoIDSeq() (int, int) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		now := time.Now().UnixNano()
		return int(now & 0xffff), int((now >> 16) & 0xffff)
	}
	id := int(binary.BigEndian.Uint16(b[:2]))
	seq := int(binary.BigEndian.Uint16(b[2:]))
	return id, seq
}
