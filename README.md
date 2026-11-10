# iPhone Activation Diagnostics Research Toolkit

This repository contains read-only diagnostics and evidence-analysis utilities
for investigating an iPhone that is stuck at Activation Lock.

## Current tools

| File | Purpose |
|---|---|
| `diagnostics.py` | Collects Windows Apple USB/PnP and local tool diagnostics |
| `cve_scope.py` | Checks device model/version against the published CVE-2025-43534 scope |
| `activation_log_analyzer.py` | Analyzes an already-captured iOS syslog offline and identifies activation-related evidence |
| `poc_audit.py` | Inventories a research bundle, hashes files, and flags unsafe ZIP entry names without extraction or execution |

## Run on Windows

From the repository directory:

```powershell
py -3 diagnostics.py --output iphone-diagnostics.json
py -3 cve_scope.py --udid YOUR_DEVICE_UDID
py -3 activation_log_analyzer.py .\activation-filtered.log --output activation-log-analysis.json
py -3 poc_audit.py .\research-bundle.zip --output poc-audit.json
```

The tools write JSON reports. Review and redact reports before sharing them.

## Development and verification

Tests are collected by GitHub Actions on pushes and pull requests to `main`.
Local test command:

```powershell
py -3 -m unittest discover -s tests -v
```

Tests have been added for the current tools; run them after the development
work is complete.

## Research boundaries

The toolkit is intended to establish device state, transport health, advisory
applicability, and what the available logs or research artifacts actually prove.
It does not execute third-party PoCs, extract untrusted archives, contact
activation servers, alter firmware, forge activation records, or change
Activation Lock. A device/version falling within a vendor advisory range is
not proof that a particular exploit works on that device.
