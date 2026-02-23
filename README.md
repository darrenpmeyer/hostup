# hostup

`hostup` is a lightweight Go CLI that checks whether a host is reachable.

It accepts a single hostname or IP address (IPv4 or IPv6), resolves hostnames (with optional DNS server override), and then checks reachability using:

- ICMP echo (default), or
- TCP connect (`-p <port>`)

## Getting Started

### Build

Build for your current OS/architecture:

```sh
make
```

This produces `./hostup`.

Build cross-platform binaries (mac/Linux x64/arm64):

```sh
make nix
```

Run the smoke tests (uses the existing `./hostup` binary; does not build):

```sh
make test
```

### Basic Usage

Check a host:

```sh
./hostup example.com
```

`hostup` exits with:

- `0` if the host is reachable
- `1` if hostname lookup fails
- `2` if lookup succeeds but the probe fails
- `120` for invalid arguments

### Example Script: Print `Up` or `DOWN`

This script prints `Up` when a host is reachable and `DOWN` when it is not reachable (including name lookup failure):

```sh
#!/usr/bin/env zsh

host="${1:-example.com}"

./hostup "$host"
case $? in
  0) echo "Up" ;;
  1|2) echo "DOWN" ;;
  *) echo "ERROR" ;;
esac
```

Example with a TCP port check:

```sh
./hostup -p 443 example.com
```

## Command Reference

### Synopsis

```sh
hostup [options] <hostname-or-ip>
```

### Behavior

- If the argument is an IP address, `hostup` probes it directly.
- If the argument is a hostname:
  - validates the hostname syntax
  - resolves it using the OS resolver by default, or `-d` if provided
  - prefers IPv6 first, then falls back to IPv4 (default behavior)
- Reachability probe:
  - ICMP echo by default
  - TCP connect when `-p <port>` is set

### Options

- `-t <ms>`: probe timeout in milliseconds (default `200`)
- `-d <host[:port]>`: Use a specific DNS server instead of OS-native name resolution
- `-p <port>`: use TCP connect (SYN) to the given port instead of ICMP echo
- `-4`: resolve hostnames to IPv4 only
- `-6`: resolve hostnames to IPv6 only
- `-4 -6`: same as default behavior (prefer IPv6, fall back to IPv4)
- `-v`: print the IP address used (stdout), whether provided directly or resolved
- `-vv`: verbose step logging to stderr, and implies `-v`

### Exit Codes

- `0`: host is reachable (ICMP reply or TCP connect succeeded)
- `1`: hostname lookup failed
- `2`: hostname lookup succeeded (or IP was valid) but reachability probe failed
- `120`: invalid arguments (help shown)

### Examples

ICMP check:

```sh
./hostup example.com
```

TCP port check:

```sh
./hostup -p 443 example.com
```

Custom timeout (50ms):

```sh
./hostup -t 50 192.0.2.10
```

Use a specific DNS server:

```sh
./hostup -d 1.1.1.1 example.com
./hostup -d 1.1.1.1:53 example.com
```

Prefer IPv4 only:

```sh
./hostup -4 example.com
```

Capture the IP address if resolved:

```sh
IP4="$(./hostup -4 -v example.com)"
IP6="$(./hostup -6 -v example.com)"
```

> NOTE: IP address is printed and captured even if the host ping/connect fails

Verbose diagnostics:

```sh
./hostup -vv -p 443 example.com
```
