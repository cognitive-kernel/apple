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
GitHub Actions run 42832092029 for commit afd55a5d96068e484f912413d4b3d2e682c40472 completed successfully. All six Ubuntu/Windows × Python 3.10/3.11/3.12 jobs passed. This run predates the IPSW inspector and does not validate the new code.

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


## 7. Follow-up research — IPSW metadata inspection (2026-11-10)

### Confirmed target firmware identity
- **Secondary-catalog observation, not a fresh device capture:** the catalog lists iPhone 16 / iPhone17,3 / iOS 18.3.2 / build 22D82, filename iPhone17,3_18.3.2_22D82_Restore.ipsw, and SHA-256 563605a932de2643bc4dcec6f312a0a0e9411cf07900a7187edb2669cb948247.
- The same catalog reports this IPSW is no longer signed. This is a secondary-source observation, not a live Apple TSS query.
- Source: https://ipsw.me/download/iPhone17%2C3/22D82/
- The download link redirects to Apple's CDN: https://updates.cdn-apple.com/2025WinterFCS/fullrestores/082-03679/DA16409C-A02F-46E9-ADE9-ED32BDD47539/iPhone17%2C3_18.3.2_22D82_Restore.ipsw. The SHA-256 above is the secondary catalog's checksum; it is not an Apple digital signature.
- **Safety decision:** do not attempt Restore, Update, downgrade, or firmware installation. The project only needs offline metadata inspection.

### New project code
- Added ipsw_inspect.py: opens an IPSW as a ZIP container, reads only the root BuildManifest.plist, checks target ProductType / ProductVersion / ProductBuildVersion, hashes the full IPSW and manifest, and optionally compares a caller-supplied SHA-256.
- The inspector does not extract archive members, install firmware, connect to the phone, or change activation state.
- It explicitly reports that Apple cryptographic signature verification and TSS signing-status checks are not performed. A self-consistent BuildManifest is not proof of publisher authenticity.
- Added tests/test_ipsw_inspect.py for matching metadata, model mismatch, version/build mismatch, checksum comparison, and missing-manifest rejection.
- Added a README command for offline use.
- Commits: 8b1ad8fd5fbdb67899738184b7b0de954deb8502 (tool), 380dbcf8841022101685e4f9aae5232af6adbd7f (tests), 4c6f119864dd867a99fc3f371f59fba97c741f90 (README).

### CI status
- The preceding commit afd55a5d96068e484f912413d4b3d2e682c40472 passed GitHub Actions run 42832092029; all six Ubuntu/Windows × Python 3.10/3.11/3.12 jobs completed successfully.
- The new IPSW inspector and its tests were added after that run. Their CI status is not yet established and must not be described as passing until a new run completes.

### Remaining validation
1. Run the new unit tests in GitHub Actions on the latest branch head.
2. Review the inspector source and test results for cross-platform behavior.
3. Only after CI succeeds, use the tool against a locally obtained IPSW file if the user already has one; do not ask for another device snapshot or repeat USB diagnostics.
4. Continue the read-only activation architecture and researcher-material review. No exploitability claim is made.


## 8. Non-invasive device-test preflight (2026-11-10)

- Added activation_preflight.py to combine the existing privacy-minimized activation snapshot with the IPSW inspector report.
- The preflight checks exact ProductType, ProductVersion, BuildVersion, Unactivated state, read-only snapshot flag, identifier-exclusion flags, IPSW manifest/checksum result, and matching expected target.
- A passing result authorizes only the next scope of read-only observation. It does not enable or authorize exploit execution, firmware changes, filesystem writes, activation-record changes, or Activation Lock modification.
- Added tests/test_activation_preflight.py for a matching case, mismatched build, unknown activation state, failed IPSW checksum status, and identifier inclusion.
- README now documents both IPSW inspection and preflight commands.
- Commits: 16c92f9b69b8911e21a2e021de89ffae2b028359 (initial preflight), 1a9151f765b04758acf3d1d4ba38c4773b7d1ce4 (schema correction), 4f813b3126b7978ac99a2794a592d6287ccae7ce (tests), 0803fff41aa1493ed34e7e63d0c4ebad1be23ebd (test schema correction), 8169e2d2cc06771a45b1dcae6cfadbfea672bcbf (README).
- GitHub Actions run 42832944559 (run #51) was pending for the commit that included the preflight code when last checked. Do not claim it passed until all six matrix jobs finish.

## 9. Updated researcher evidence (2026-11-10)

- The credited researcher's portfolio (https://ig0x72.dev/) describes CVE-2025-43534 as an iOS sandbox escape in itunesstored, involving malicious SQLite database manipulation and arbitrary file writes outside the app sandbox; the page lists Activation Lock bypass as impact.
- The linked article (https://ig0x72.dev/posts/wip.html) remained marked "Work in Progress" at review time. No detailed public reproduction steps or validated iPhone17,3 / iOS 18.3.2 test result were available there.
- The researcher's GitHub profile (https://github.com/iG0x72) showed three public repositories at review time; none was identified from the visible repository list as a published CVE-2025-43534 reproduction.
- This is a **Researcher-claimed** description, not an independently reproduced exploit.
- The bl_sbx artifact remains separate: the thematic overlap is noted, but no direct attribution or proof that it is the CVE implementation has been established.


## 10. CI validation update (2026-11-10)

- GitHub Actions run 42832998621 (run #53) completed successfully for the branch head containing both new utilities.
- The workflow run is now completed with conclusion **success**. All six Ubuntu/Windows × Python 3.10/3.11/3.12 jobs passed compilation and unit tests. The Windows/Python 3.10 job log reports **40 tests, OK**.
- The Windows/Python 3.10 job log includes the five IPSW inspector tests and reports 40 total tests passing.
- Separate local focused verification passed all 10 tests for ipsw_inspect.py and activation_preflight.py.
- This is GitHub Actions evidence, not a test performed against the physical iPhone or a real 8.8 GiB IPSW. No firmware file was downloaded, no restore was attempted, and the device was not modified.
