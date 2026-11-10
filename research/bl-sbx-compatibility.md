# Public PoC Compatibility Assessment

Assessment date: 2026-11-10

## Artifact identity

- Repository: https://github.com/hanakim3945/bl_sbx
- Default branch: main
- Repository description: iTunesStored and bookassetd sandbox escape
- Main tree commit: 4832e5b6ecca0a0983492b8807148204e1162a2f
- Repository tree contains five artifacts: two SQLite databases, one EPUB, one plist, and README.
- README artifact hash (Git blob): d56b84ee183d4dfa52cd8531f82fbc1239509a43

## What the publisher actually claims

The repository README describes a sandbox-escape proof of concept involving the iOS daemons itunesstored and bookassetd. Its stated outcome is writing files owned by the mobile user in selected locations and using a MobileGestalt cache modification as a demonstration.

The README does not state that it removes Activation Lock, creates a valid activation record, changes Apple's server-side device association, or restores normal cellular activation. Therefore this repository is not evidence of a working Activation Lock removal method.

## Compatibility against the target device

| Attribute | PoC publisher's stated test | Target device | Assessment |
|---|---|---|---|
| Model | iPhone 12 | iPhone 16 (iPhone17,3, A3288) | Different model; not validated |
| iOS | 26.0.1 | 18.3.2 (22D82) | Different major/minor branch; not validated |
| Upper range | README says up to 26.2 beta 1 | 18.3.2 | Publisher claim does not establish this older branch |
| Result | Mobile-owned file-write primitive | Activation Lock removal required | Required outcome not demonstrated |

The CVE-2025-43534 vendor advisory scope and this public sandbox-escape PoC are separate evidence items. No verified source in this assessment establishes that the repository PoC is the implementation of CVE-2025-43534.

## Device-side prerequisites: evidence status

The research article describes an existing local filesystem foothold and USB file transfer access as prerequisites. The target device previously returned successful pairing validation and exposed AFC tooling in the user's Windows environment. Those facts establish that a pairing/AFC interface was available in that earlier session; they do not establish write access to the specific databases or system-group locations, and they do not establish that either daemon will process modified metadata on this device.

The current project deliberately does not test by replacing system databases, supplying crafted download metadata, rebooting into an exploit chain, modifying FairPlay state, or changing activation records.

## Evidence ledger

| Claim | Status | Reason |
|---|---|---|
| Public repository exists and is accessible | Confirmed | GitHub repository metadata and tree were retrieved |
| Publisher claims a sandbox escape | Publisher claim | README description |
| Publisher tested iPhone 12 / iOS 26.0.1 | Publisher claim | README wording |
| Target iPhone 16 / iOS 18.3.2 is compatible | Unverified | No target-device validation or matching test report |
| PoC is CVE-2025-43534 | Unverified | No source-level linkage established |
| PoC removes Activation Lock | Not demonstrated | README only documents file-write/MobileGestalt result |
| Apple's activation server accepts the device afterward | Unknown | No valid activation response/record evidence |

## Conclusion

The public PoC is not currently a demonstrated solution for this device. Its published result is materially narrower than the user's required result. The technically honest next step is to collect and compare non-invasive device observations and public vendor/research evidence; do not interpret AFC pairing, advisory version range, or a MobileGestalt cache write as proof that Activation Lock has been removed.

## Sources

- PoC README: https://github.com/hanakim3945/bl_sbx
- PoC repository tree: https://api.github.com/repos/hanakim3945/bl_sbx/git/trees/main?recursive=1
- HackTricks research overview: https://github.com/HackTricks-wiki/hacktricks/blob/75a688821df38d5e22201be92af82fba0c821767/src/mobile-pentesting/ios-pentesting/itunesstored-bookassetd-sandbox-escape.md
- Apple security advisory: https://support.apple.com/en-md/126793
