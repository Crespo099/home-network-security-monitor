"""Bounded, consent-gated inventory of a small private IPv4 subnet."""
import argparse
import csv
import ipaddress
import json
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

MAX_HOSTS = 256


def validate_subnet(value: str):
    net = ipaddress.ip_network(value, strict=False)
    rfc1918 = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]
    if not isinstance(net, ipaddress.IPv4Network) or not any(net.subnet_of(block) for block in rfc1918):
        raise ValueError("Only RFC1918 IPv4 subnets are accepted.")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"Subnet exceeds the {MAX_HOSTS}-address limit.")
    return net


def probe(address: str):
    system = platform.system().lower()
    args = ["ping", "-n" if system == "windows" else "-c", "1", "-w" if system == "windows" else "-W", "1000" if system == "windows" else "1", address]
    try:
        result = subprocess.run(args, capture_output=True, timeout=2, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def inspect_host(address: str):
    try:
        hostname = socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror):
        hostname = ""
    return {"ip": address, "reachable": probe(address), "hostname": hostname}


def collect(subnet: str):
    network = validate_subnet(subnet)
    hosts = [inspect_host(str(ip)) for ip in network.hosts()]
    return {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "subnet": str(network), "method": "single bounded ICMP echo per address; optional reverse DNS", "devices": hosts}


def write_report(report, output: Path, fmt: str):
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with output.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "reachable", "hostname"])
            writer.writeheader(); writer.writerows(report["devices"])
    else:
        lines = ["# Network inventory", "", f"- Generated (UTC): {report['generated_at_utc']}", f"- Subnet: {report['subnet']}", "", "| IP | Reachable | Hostname |", "|---|---|---|"]
        lines += [f"| {d['ip']} | {'Yes' if d['reachable'] else 'No'} | {d['hostname'] or '—'} |" for d in report["devices"]]
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subnet", help="Private IPv4 CIDR, for example 192.168.1.0/24")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own or are authorized to assess this network")
    parser.add_argument("--output", type=Path, default=Path("reports/inventory.json"))
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument("--example", action="store_true", help="Write synthetic sample inventory; performs no network probes")
    args = parser.parse_args()
    if args.example:
        report = {"generated_at_utc": "2026-01-01T00:00:00+00:00", "subnet": "192.168.1.0/24", "method": "synthetic example; no probes performed", "devices": [{"ip":"192.168.1.1","reachable":True,"hostname":"router.example"},{"ip":"192.168.1.23","reachable":True,"hostname":"laptop.example"}]}
    else:
        if not args.authorized:
            parser.error("network probing requires --authorized")
        if not args.subnet:
            parser.error("--subnet is required unless --example is used")
        try:
            report = collect(args.subnet)
        except ValueError as exc:
            parser.error(str(exc))
    write_report(report, args.output, args.format)
    print(f"Wrote {args.format} inventory to {args.output}")

if __name__ == "__main__":
    main()



