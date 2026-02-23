#!/usr/bin/env zsh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Darren P Meyer

emulate -L zsh
setopt pipefail no_unset

typeset -gi PASS_COUNT=0
typeset -gi FAIL_COUNT=0
typeset -gi SKIP_COUNT=0
typeset -gi CASE_NUM=0

typeset -g CASE_NAME=""
typeset -g CASE_STDOUT=""
typeset -g CASE_STDERR=""
typeset -gi CASE_EXIT=0
typeset -gi CASE_OK=1

TMPDIR_CASES="$(mktemp -d "${TMPDIR:-/tmp}/hostup-smoke.XXXXXX")" || exit 1
trap 'rm -rf "$TMPDIR_CASES"' EXIT

if [[ ! -x ./hostup ]]; then
  print -u2 -- "error: ./hostup is not executable. Build first (e.g. go build -o hostup .)"
  exit 1
fi

begin_case() {
  CASE_NUM=$((CASE_NUM + 1))
  CASE_NAME="$1"
  CASE_OK=1
  CASE_STDOUT=""
  CASE_STDERR=""
  CASE_EXIT=0
  print -- ""
  print -- "[$CASE_NUM] $CASE_NAME"
}

run_case_cmd() {
  local out_file="$TMPDIR_CASES/out.$CASE_NUM"
  local err_file="$TMPDIR_CASES/err.$CASE_NUM"
  local -a cmd=( "$@" )

  print -- "+ ${cmd[*]}"
  "${cmd[@]}" >"$out_file" 2>"$err_file"
  CASE_EXIT=$?
  CASE_STDOUT="$(<"$out_file")"
  CASE_STDERR="$(<"$err_file")"

  print -- "  exit: $CASE_EXIT"
  if [[ -n "$CASE_STDOUT" ]]; then
    print -- "  stdout:"
    print -- "$CASE_STDOUT" | sed 's/^/    /'
  fi
  if [[ -n "$CASE_STDERR" ]]; then
    print -- "  stderr:"
    print -- "$CASE_STDERR" | sed 's/^/    /'
  fi
}

expect_code() {
  local expected="$1"
  if [[ $CASE_EXIT -ne $expected ]]; then
    print -- "  check failed: expected exit $expected"
    CASE_OK=0
  fi
}

expect_code_any() {
  local matched=1
  local code
  for code in "$@"; do
    if [[ $CASE_EXIT -eq $code ]]; then
      matched=0
      break
    fi
  done
  if (( matched != 0 )); then
    print -- "  check failed: expected exit in (${(j:, :)@})"
    CASE_OK=0
  fi
}

expect_stdout_exact() {
  local expected="$1"
  if [[ "$CASE_STDOUT" != "$expected" ]]; then
    print -- "  check failed: expected stdout exactly: $expected"
    CASE_OK=0
  fi
}

expect_stdout_contains() {
  local needle="$1"
  if [[ "$CASE_STDOUT" != *"$needle"* ]]; then
    print -- "  check failed: stdout missing: $needle"
    CASE_OK=0
  fi
}

expect_stderr_contains() {
  local needle="$1"
  if [[ "$CASE_STDERR" != *"$needle"* ]]; then
    print -- "  check failed: stderr missing: $needle"
    CASE_OK=0
  fi
}

mark_skip() {
  local reason="$1"
  SKIP_COUNT=$((SKIP_COUNT + 1))
  print -- "  result: SKIP ($reason)"
}

end_case() {
  if (( CASE_OK )); then
    PASS_COUNT=$((PASS_COUNT + 1))
    print -- "  result: PASS"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    print -- "  result: FAIL"
  fi
}

localhost_v4=""
localhost_v6=""
default_localhost_ip=""
both_localhost_ip=""

begin_case "help exits 0 and documents exit codes"
run_case_cmd ./hostup -h
expect_code 0
expect_stderr_contains "Usage: hostup"
expect_stderr_contains "Exit codes:"
expect_stderr_contains "120 Invalid arguments"
end_case

begin_case "invalid hostname prints help and exits 120"
run_case_cmd ./hostup 'bad host'
expect_code 120
expect_stderr_contains "invalid host/IP argument"
end_case

begin_case "missing hostname argument exits 120"
run_case_cmd ./hostup -v
expect_code 120
expect_stderr_contains "Usage: hostup"
end_case

begin_case "invalid timeout exits 120"
run_case_cmd ./hostup -t 0 127.0.0.1
expect_code 120
expect_stderr_contains "Usage: hostup"
end_case

begin_case "invalid port exits 120"
run_case_cmd ./hostup -p 70000 127.0.0.1
expect_code 120
expect_stderr_contains "Usage: hostup"
end_case

begin_case "unresolvable hostname exits 1"
run_case_cmd ./hostup nosuchhost-hostup-invalid.example
expect_code 1
end_case

begin_case "custom DNS server (host only, default port 53) parses and reports lookup failure"
run_case_cmd ./hostup -d 127.0.0.1 nosuchhost-hostup-invalid.example
expect_code 1
end_case

begin_case "custom DNS server with explicit port parses and reports lookup failure"
run_case_cmd ./hostup -d 127.0.0.1:53 nosuchhost-hostup-invalid.example
expect_code 1
end_case

begin_case "-v prints provided IP even when probe fails"
run_case_cmd ./hostup -v -p 1 127.0.0.1
expect_code 2
expect_stdout_exact "127.0.0.1"
end_case

begin_case "-vv prints step logs and final exit code (hostname after flags)"
run_case_cmd ./hostup -vv -p 1 127.0.0.1
expect_code 2
expect_stdout_exact "127.0.0.1"
expect_stderr_contains "processing target"
expect_stderr_contains "tcp probe"
expect_stderr_contains "exit with code 2"
end_case

begin_case "hostname/IP can appear before flags"
run_case_cmd ./hostup 127.0.0.1 -vv -p 1
expect_code 2
expect_stdout_exact "127.0.0.1"
expect_stderr_contains "exit with code 2"
end_case

begin_case "default hostname resolution prefers IPv6 (localhost)"
run_case_cmd ./hostup localhost -v -p 1
expect_code 2
if [[ -n "$CASE_STDOUT" ]]; then
  default_localhost_ip="$CASE_STDOUT"
fi
if [[ "$CASE_STDOUT" == "::1" ]]; then
  :
else
  print -- "  note: expected ::1 on systems with IPv6 localhost"
fi
end_case

begin_case "-4 uses IPv4 for hostname resolution"
run_case_cmd ./hostup localhost -v -p 1 -4
expect_code 2
localhost_v4="$CASE_STDOUT"
expect_stdout_exact "127.0.0.1"
end_case

begin_case "-6 uses IPv6 for hostname resolution"
run_case_cmd ./hostup localhost -v -p 1 -6
if [[ $CASE_EXIT -eq 1 ]]; then
  mark_skip "system does not provide IPv6 localhost resolution"
else
  expect_code 2
  localhost_v6="$CASE_STDOUT"
  expect_stdout_exact "::1"
  end_case
fi

begin_case "-4 and -6 together behave like default (prefer v6, fallback v4)"
run_case_cmd ./hostup localhost -v -p 1 -4 -6
expect_code 2
both_localhost_ip="$CASE_STDOUT"
if [[ -n "$default_localhost_ip" && "$both_localhost_ip" != "$default_localhost_ip" ]]; then
  print -- "  check failed: expected same IP as default resolution ($default_localhost_ip)"
  CASE_OK=0
fi
end_case

begin_case "-t (timeout ms) accepts custom value in mixed argument order"
run_case_cmd ./hostup 127.0.0.1 -t 50 -p 1 -v
expect_code 2
expect_stdout_exact "127.0.0.1"
end_case

begin_case "ICMP path smoke (may fail in restricted environments)"
run_case_cmd ./hostup -t 50 127.0.0.1
expect_code_any 0 2
if [[ $CASE_EXIT -eq 2 && "$CASE_STDERR" == *"operation not permitted"* ]]; then
  print -- "  note: ICMP blocked in this environment"
fi
end_case

print -- ""
print -- "Summary: PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT"
if (( FAIL_COUNT > 0 )); then
  exit 1
fi
exit 0
