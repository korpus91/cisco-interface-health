#!/usr/bin/env python3
"""
cisco-interface-health: offline triage of Cisco IOS / IOS-XE "show interfaces" output.

Paste or save the output of "show interfaces" (one or many devices) and get a
ranked list of interfaces with error counters that point at a physical or
configuration problem: CRC, duplex mismatch, runts/giants, drops, flapping,
err-disabled.

Offline and read-only: it parses text, it never connects to a device.

Usage
  python ifhealth.py show_int.txt
  python ifhealth.py show_int.txt --csv findings.csv
  type show_int.txt | python ifhealth.py -

Exit codes: 0 clean, 1 findings, 2 error.
"""
import argparse
import csv
import re
import sys
from dataclasses import dataclass, field

# EDIT: thresholds
RESET_THRESHOLD = 10        # interface resets above this suggest flapping
CRC_RATE_CRITICAL = 0.0001  # CRC / input packets above 0.01% is critical
DROP_RATE_WARN = 0.001      # output drops / output packets above 0.1%

RE_HEADER = re.compile(
    r"^(?P<name>\S+) is (?P<status>administratively down|up|down), "
    r"line protocol is (?P<proto>up|down)(?: \((?P<reason>[^)]+)\))?"
)
RE_DUPLEX = re.compile(r"(?P<duplex>Full|Half|Auto|full|half|auto)[- ]duplex,\s*(?P<speed>[^,]+)")
RE_COUNTERS = {
    "packets_in": re.compile(r"(\d+) packets input"),
    "packets_out": re.compile(r"(\d+) packets output"),
    "input_errors": re.compile(r"(\d+) input errors"),
    "crc": re.compile(r"(\d+) CRC"),
    "runts": re.compile(r"(\d+) runts"),
    "giants": re.compile(r"(\d+) giants"),
    "output_errors": re.compile(r"(\d+) output errors"),
    "collisions": re.compile(r"(\d+) collisions"),
    "resets": re.compile(r"(\d+) interface resets"),
    "late_collisions": re.compile(r"(\d+) late collision"),
    "output_drops": re.compile(r"Total output drops: (\d+)"),
}


@dataclass
class Interface:
    name: str
    status: str
    protocol: str
    reason: str = ""
    duplex: str = ""
    speed: str = ""
    counters: dict = field(default_factory=dict)

    def c(self, key: str) -> int:
        return self.counters.get(key, 0)


@dataclass
class Finding:
    interface: str
    severity: str  # critical | warning
    issue: str
    detail: str
    action: str


def parse(text: str) -> list[Interface]:
    interfaces, cur = [], None
    for line in text.splitlines():
        m = RE_HEADER.match(line)
        if m:
            cur = Interface(m["name"], m["status"], m["proto"], m["reason"] or "")
            interfaces.append(cur)
            continue
        if cur is None:
            continue
        m = RE_DUPLEX.search(line)
        if m and not cur.duplex:
            cur.duplex = m["duplex"].capitalize()
            cur.speed = m["speed"].strip()
        for key, rx in RE_COUNTERS.items():
            m = rx.search(line)
            if m:
                cur.counters[key] = int(m.group(1))
    return interfaces


def assess(intf: Interface) -> list[Finding]:
    f: list[Finding] = []
    add = lambda sev, issue, detail, action: f.append(Finding(intf.name, sev, issue, detail, action))

    if "err-disabled" in intf.reason:
        add("critical", "err-disabled", intf.reason,
            "Check 'show interfaces status err-disabled' for the cause, fix it, then shut/no shut.")

    crc, pin = intf.c("crc"), intf.c("packets_in")
    if crc:
        rate = crc / pin if pin else 1.0
        add("critical" if rate > CRC_RATE_CRITICAL else "warning", "CRC errors",
            f"{crc} CRC ({rate:.4%} of input)",
            "Layer 1: reseat or replace cable and optic, check patch panel, then duplex.")

    if intf.c("late_collisions") or (intf.duplex == "Half" and intf.status == "up"):
        add("critical", "Duplex mismatch likely",
            f"{intf.duplex or '?'}-duplex, {intf.c('late_collisions')} late collisions",
            "Set both ends to auto/auto (or both hard-coded identically) and clear counters.")

    if intf.c("runts") or intf.c("giants"):
        add("warning", "Runts/giants", f"{intf.c('runts')} runts, {intf.c('giants')} giants",
            "Runts: duplex or bad NIC. Giants: MTU mismatch between neighbors.")

    drops, pout = intf.c("output_drops"), intf.c("packets_out")
    if drops and (not pout or drops / pout > DROP_RATE_WARN):
        add("warning", "Output drops", f"{drops} drops" + (f" ({drops / pout:.3%})" if pout else ""),
            "Congestion: check utilization, QoS queueing and microbursts.")

    if intf.c("resets") > RESET_THRESHOLD:
        add("warning", "Interface resets", f"{intf.c('resets')} resets",
            "Possible flapping: check logging for link up/down, keepalives, power.")

    return f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Triage Cisco 'show interfaces' output offline")
    p.add_argument("input", help="file with show interfaces output, or - for stdin")
    p.add_argument("--csv", help="also write findings to this CSV file")
    args = p.parse_args(argv)
    try:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    interfaces = parse(text)
    if not interfaces:
        print("error: no interfaces found in input", file=sys.stderr)
        return 2

    findings = [x for i in interfaces for x in assess(i)]
    findings.sort(key=lambda x: (x.severity != "critical", x.interface))

    print(f"Parsed {len(interfaces)} interfaces, {len(findings)} findings.")
    for x in findings:
        print(f"[{x.severity.upper():8}] {x.interface:28} {x.issue}: {x.detail}\n{'':40}-> {x.action}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["interface", "severity", "issue", "detail", "action"])
            w.writerows([[x.interface, x.severity, x.issue, x.detail, x.action] for x in findings])

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
