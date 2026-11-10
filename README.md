# iPhone Activation Diagnostics Research Toolkit

This repository contains read-only diagnostics and evidence-analysis utilities
for investigating an iPhone that is stuck at Activation Lock.

## Current tools

| File | Purpose |
|---|---|
| `diagnostics.py` | Collects Windows Apple USB/PnP and local tool diagnostics |
| `cve_scope.py` | Checks device model/version against the published CVE-2025-43534 scope |
| `target_assessment.py` | Combines vendor advisory applicability with published PoC test evidence; explicitly reports when no validated Activation Lock solution is demonstrated |
| `ipsw_inspect.py` | Reads an IPSW BuildManifest.plist, hashes the archive, and compares model/version/build without extracting or installing firmware |
| `snapshot_diff.py` | Compares two device snapshots and reports observed property changes |
| `activation_snapshot.py` | Captures selected activation/baseband/SIM properties without collecting serial, UDID, or ECID |
| `activation_log_analyzer.py` | Analyzes an already-captured iOS syslog offline and identifies activation-related evidence |
| `poc_compatibility.py` | Compares a read-only device snapshot with the public PoC's published test environment |
| `poc_audit.py` | Inventories a research bundle, hashes files, and flags unsafe ZIP entry names without extraction or execution |

## Run on Windows

From the repository directory:

```powershell
py -3 ipsw_inspect.py .\iPhone17,3_18.3.2_22D82_Restore.ipsw --output ipsw-report.json
py -3 activation_snapshot.py --output activation-snapshot.json
py -3 target_assessment.py .\activation-snapshot.json --output target-assessment.json
py -3 diagnostics.py --output iphone-diagnostics.json
py -3 activation_log_analyzer.py .\activation-filtered.log --output activation-log-analysis.json
py -3 poc_audit.py .\research-bundle.zip --output poc-audit.json
```

The IPSW inspector reads only the root `BuildManifest.plist`, computes a full-file SHA-256, and never extracts or installs firmware. A matching manifest is not cryptographic proof that Apple signed the archive. It does not check TSS signing status. The tool is for offline evidence validation only; do not select Restore or Update as part of this inspection.

The tools write JSON reports. Review and redact reports before sharing them.

## Development and verification

Tests are collected by GitHub Actions on pushes and pull requests to `main`.
Local test command:

```powershell
py -3 -m unittest discover -s tests -v
```

## Research notes

- `research/cve-2025-43534-attribution.md` records Apple's CVE attribution and separates vendor-confirmed facts from researcher statements.
- `research/bl-sbx-compatibility.md` assesses the separate public PoC against the target device.
- `research/target-investigation-log.md` is the continuity record for this iPhone 16 case: prior checks, reported results, completed repository tests, reviewed PoCs, evidence gaps, and the rule against repeating diagnostics without a new reason.

## Research boundaries

The toolkit establishes device state, transport health, advisory applicability,
and what available logs or research artifacts actually prove. It does not
execute third-party PoCs, extract untrusted archives, contact activation
servers, alter firmware, forge activation records, or change Activation Lock.
A device/version falling within a vendor advisory range is not proof that a
particular exploit works on that device.
