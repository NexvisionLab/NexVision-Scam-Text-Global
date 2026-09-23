# Public release report — v0.2.1

Release date: 2026-09-23  
Project: NexVision ScamText Global  
Repository: `NexvisionLab/scamtext-global`

## Release decision

**Approved for controlled offline research, taxonomy development and regression
testing. Not approved as evidence of production detection performance.**

## Scope

The reference build contains 1,500,000 deterministic synthetic records across
50 language labels, 21 scripts and 60 scam families. The public Git repository
contains source code, tests, documentation and offline anchor data. Bulk
generated shards are excluded from Git history and can be recreated exactly
from the documented command.

## Security and privacy audit

The publication tree was checked for credential patterns, private keys, common
API-token formats, email addresses, phone-like contact data, local environment
files, personal names, unsafe execution paths, network clients and unsafe
deserialization. No secrets or personal contact details were found. Project and
organization identifiers intentionally retained are `NexVision Lab` and the
public GitHub account `NexvisionLab`.

The executable code uses only the Python standard library. It contains no
runtime network call, subprocess invocation, dynamic `eval`/`exec`, pickle or
YAML deserialization. Manifest paths are constrained to the dataset root, and
generated files are authenticated by size and SHA-256 digest.

## Verification results

| Check | Result |
|---|---:|
| Python compilation | Passed |
| Regression tests | 26 / 26 passed |
| Representative 15,000-record generation | Passed |
| Representative streaming validation | Passed |
| Full 1,500,000-record reference validation | Passed |
| Language–family coverage | 3,000 / 3,000 |
| Split leakage across protected cluster types | 0 |
| Live URLs in reference build | 0 |
| Third-party runtime dependencies | 0 |
| Exposed credentials or personal contact details | 0 found |

## Controls included

- Defanged links use reserved bracketed `.invalid` hosts.
- Records assert `pii_present: false` and `safety_status: defanged`.
- Generation is transactional and preserves a prior valid output after failure.
- Generation refuses filesystem roots, symbolic-link outputs and nonempty
  directories that are not recognized ScamText dataset outputs.
- Validation rejects path traversal, duplicate manifest paths, undeclared
  shards, malformed identifiers, invalid label semantics and hash mismatches.
- The tests cover all confirmed defects fixed in v0.2.1.

## Remaining limitations

1. The release is synthetic and does not measure real-world sensitivity,
   specificity, calibration or prevalence.
2. No language is fully native-reviewed; 32 languages use smaller generic seed
   packs and 18 use deeper but still unapproved anchor packs.
3. Independent validation separated by campaign, sender, domain and time has
   not been completed.
4. Per-language operational thresholds, drift monitoring, incident response and
   analyst review remain future production controls.
5. Synthetic templates cannot capture every dialect, code-switching pattern,
   typo, social context or evolving campaign.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial License
1.0.0. Commercial use, paid services, commercial redistribution, production
deployment and hosted services require a separate written licence from
NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
