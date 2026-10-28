# Home Network Security Monitor

This project is a small Python CLI for authorized inventory of a home or lab network. It accepts only RFC1918 IPv4 subnets of at most 256 addresses, requires an explicit authorization flag, sends one bounded ping probe per address, optionally resolves reverse DNS, and exports JSON, CSV, or Markdown.

## Safety scope

The monitor does not scan ports, capture traffic, test credentials, or change router settings. Use it only on a network you own or have permission to assess. Firewall rules may block ping, and hostnames may be unavailable. Reachability is not proof of device identity.

## Run in VS Code

Requires Python 3.10 or newer. No third-party packages are required.

```powershell
python -m src.monitor --example --output reports/example.json
python -m src.monitor --subnet 192.168.1.0/24 --authorized --output reports/inventory.json
python -m src.monitor --subnet 192.168.1.0/24 --authorized --format csv --output reports/inventory.csv
```

Use `--format markdown` for a readable report. The example mode uses synthetic data and performs no probes.

## Career relevance

Demonstrates foundational Python, IPv4/CIDR validation, bounded OS-level diagnostics, reverse DNS, structured reports, and safety-aware troubleshooting. The lab guide connects observations to DHCP, DNS, gateways, Wi-Fi, switch ports, and VLAN concepts. It is an educational inventory aid, not a complete security monitoring system.

## Status

Initial portfolio implementation. Validate it in an authorized lab before presenting live scan results.

