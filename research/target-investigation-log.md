# Target investigation log — iPhone 16 Activation Lock

Last consolidated: 2026-11-10  
Target: iPhone 16, ProductType `iPhone17,3`, A18, reported iOS `18.3.2` / build `22D82`.

## Purpose and continuity rule

This file is the durable record of prior investigations for this target. Read it before asking the user to repeat a diagnostic, collect another snapshot, reinstall a driver, retry account recovery, or revisit a third-party project.

**Do not request a previously completed check again** unless a new, explicit hypothesis requires a fresh observation (for example, the device's connection mode has changed, a different host is being used, or a new firmware/build is installed). Explain what changed and what the new test will distinguish. Treat reported historical results as historical, not as proof of the device's current state.

This record intentionally excludes IMEI, serial number, UDID, ECID, MAC addresses, Apple Account addresses, passwords, and invoice identifiers.

## 1. Target state and reported observations

| Item | Recorded observation | Evidence qualification |
|---|---|---|
| Device | iPhone 16, `iPhone17,3`, A18 | User-reported device details |
| OS | iOS 18.3.2, build 22D82 | User-reported; last known snapshot |
| Setup screen | `iPhone Locked to Owner` / Activation Lock | User-reported |
| Activation state | `Unactivated` | Previously reported from device tooling |
| Apple Account | Account recovery reports `This account is locked and can't be used` | User-reported |
| Personal data | Device reported to contain no needed personal data | User-reported |
| 3uTools | `HostAttached=true`, `TrustedHostAttached=true`, `BrickState=true`; not in Recovery at time of capture | Historical tool output; meanings of vendor-specific flags are not independently established |
| Windows USB/PnP | Apple USB/PnP devices and Apple USB driver were reported OK | Historical host observation |
| Apple Devices | App installed on Windows | Historical host observation |
| Pairing/AFC | Earlier research notes record successful pairing validation and AFC tooling/interface availability | Does not prove arbitrary write access, system-file access, or exploitability |
| Current live connection | Not established by this log | Must not be inferred from historical observations |

## 2. Troubleshooting already completed — do not repeat by default

### Account and ownership routes
- Apple Account password recovery was attempted; the account returned the locked-account message above.
- The user reports repeated attempts through Apple Activation Lock support/request workflow, including previous submissions and denials.
- Purchase documentation and the Iranian seller/invoice context were reviewed in earlier conversations. The user reports Apple did not accept the documentation.
- Seller and warranty avenues were reported as exhausted or unavailable.
- The user explicitly asked not to be sent back through these already-tried routes as generic advice.

These are user-reported outcomes. Do not ask for passwords, full account identifiers, invoice identifiers, IMEI, or serial numbers.

### Windows/device connection
- Windows Apple USB/PnP and driver status were checked previously and reported healthy.
- Apple Devices was already installed.
- A prior 3uTools capture did not show Recovery mode.
- A prior pairing validation/AFC interface observation is recorded above.
- Do not ask the user to rerun `diagnostics.py`, `activation_snapshot.py`, or re-check drivers merely to repeat baseline collection. The latest outputs already produced in the earlier workflow should be consulted first if available.

### Third-party project: tr4mpass
Static review of `https://github.com/tr4m0ryp/tr4mpass` was completed:
- README's stated device ceiling was iPhone 15 Pro / A17 Pro; iPhone 16 / A18 / `iPhone17,3` was not listed.
- Its checkm8 path targets A5–A11; its separate newer-device path did not establish A18 support.
- The project did not provide a validated test result for this target.
- `start.sh` was identified as an installer/launcher for the tool; it was not run.
- GitHub releases API returned no published releases at the time reviewed; the repository had no recorded license in the metadata inspected.
- A project research file exposed identifying details of a test device; this was noted as a privacy concern, not proof of malware.
- Conclusion: not validated for this device; do not ask the user to run it.

### Separate public PoC: bl_sbx
Static review of `https://github.com/hanakim3945/bl_sbx` was completed:
- Repository describes an iTunesStored/bookassetd sandbox escape and a MobileGestalt cache/file-write demonstration.
- Its stated test environment was iPhone 12 (`iPhone13,2`) on iOS 26.0.1; stated upper range was 26.2 beta 1.
- It did not claim Activation Lock removal, generation of a valid activation record, or server-side device unlinking.
- Its relationship to CVE-2025-43534 was not established.
- The device's historical pairing/AFC observation does not establish the specific filesystem permissions or prerequisites described by the research.
- No PoC code was executed and no crafted database, metadata, FairPlay state, or activation record was written.
- Conclusion: the public artifact does not validate the user's iPhone 16 / iOS 18.3.2 target or the required outcome.

## 3. CVE-2025-43534 evidence

### Vendor-confirmed
Apple's security advisory for iOS 18.7.7 identifies CVE-2025-43534 in the iTunes Store component. Apple states that a person with physical access may be able to bypass Activation Lock; the description is a path-handling issue addressed with improved validation. The advisory's device list includes iPhone 16 (all models). The fixed versions recorded in the reviewed advisories are iOS 18.7.7 and iOS 26.2.

Official source: https://support.apple.com/en-md/126793  
Related Apple advisory: https://support.apple.com/en-gb/125884

### What this establishes — and what it does not
- If the reported iOS 18.3.2 build is accurate, it is below the published iOS 18.7.7 fix for this branch.
- This is vendor-advisory applicability, not proof that a public exploit is available or that a specific exploit works on `iPhone17,3`.
- No reproducible public exploit or validated Activation Lock removal result for this exact model/build was established in the reviewed material.
- Researcher attribution/portfolio statements are not equivalent to a complete, reproducible technical write-up.
- Do not conflate the separate `bl_sbx` artifact with CVE-2025-43534 absent direct source evidence.

## 4. Project repository and implemented research tooling

Repository: https://github.com/cognitive-kernel/apple  
Research branch: `feat/cve-2025-43534-evidence-validation`  
Existing PR: https://github.com/cognitive-kernel/apple/pull/3

Tools already added/reviewed:
- `activation_snapshot.py`: privacy-minimized device property snapshot; excludes UDID, serial, and ECID from report.
- `cve_scope.py`: compares product/version against vendor advisory scope.
- `poc_compatibility.py`: compares target snapshot with published PoC claims.
- `target_assessment.py`: combines advisory applicability and PoC evidence; explicitly avoids claiming exploitability.
- `diagnostics.py`: Windows Apple USB/PnP and local tool inventory.
- `activation_log_analyzer.py`: offline analysis of a user-supplied captured log.
- `snapshot_diff.py`: compares two snapshots.
- `poc_audit.py`: static archive/directory inventory; does not execute scripts or extract archives.

### Completed local verification
On the user's Windows checkout at `D:\Project\apple\apple`:
- Branch `feat/cve-2025-43534-evidence-validation` was checked out.
- Command `py -3 -m unittest discover -s tests -v` completed with **35 tests passing**.
- `activation_snapshot.py` generated `activation-snapshot.json`; the tool reported that UDID, serial, and ECID were not included.
- `target_assessment.py` generated `target-assessment.json` with result `advisory_applies_but_no_validated_activation_lock_solution`.
- The assessment explicitly stated read-only/no exploit execution/no device modification.

### CI status at last recorded check
The PR's GitHub status endpoint had `total_count=0` and `status=pending`; this was not a CI success. Re-check CI before claiming that the PR passed hosted workflows.

## 5. Current evidence gaps and next research work

These are open questions, not completed tests:
1. Obtain and inspect a trustworthy, legally obtained copy of the exact target IPSW/build metadata; verify build identity and manifest without flashing or restoring the phone.
2. Map the public, documented iOS activation architecture and identify which observations can be obtained from existing logs or supported interfaces without changing protected state.
3. Review the complete public technical material from the credited CVE researchers if/when it becomes available; record exact source revision, hashes, target models/builds, and reproducible claims.
4. If the user provides an already captured diagnostic/log artifact, analyze that artifact before asking for another capture.
5. Keep all experiments read-only and non-destructive. No boot-chain patching, crafted SQLite/database payloads, FairPlay manipulation, activation-ticket forgery, activation-server impersonation, or changes to protected activation state are part of this project.

## 6. Evidence discipline

Every new finding must be labeled as one of:
- **Vendor-confirmed** — official Apple documentation or other primary source.
- **Observed** — direct output/artifact from this target, with date and tool/version.
- **Researcher-claimed** — a statement by a researcher/project not independently reproduced.
- **Inferred** — a reasoned interpretation with its assumptions stated.
- **Unknown / not demonstrated** — evidence is insufficient.

Never convert an advisory match, USB pairing, AFC availability, a log keyword, or a cache/file-write demonstration into a claim that Activation Lock was removed. Record negative results and failed hypotheses so they are not repeated.
