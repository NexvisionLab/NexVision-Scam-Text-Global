# Code integrity and production-readiness audit — v0.2.1

Audit date: 2026-09-23  
Scope: source, tests, dependency declaration, documentation, generated metadata,
all 15 distributed shards and the packaged release  
History review: unavailable; the supplied release was not a Git working tree

## Decision

**Controlled offline research and QA use: GO.**

**Operational scam-classification deployment: NO-GO pending external validation.**
The release is fully synthetic, no language has completed native-speaker review,
and the data cannot establish real-world sensitivity, specificity, calibration
or robustness.

## Fixed findings

Line numbers in the Location column refer to the source as it was when the finding
was made, before these fixes; they no longer match the current files.

| Severity | Classification | Location | Evidence and impact | Action |
|---|---|---|---|---|
| High | Confirmed defect | `src/generate_dataset.py:253-265`, `languages()` | Seven seed-only languages were also marked tier A, affecting 210,000 records in v0.2.0. | Tier A is now derived strictly from membership in the 18-language anchor pack; all 32 other languages are tier B. |
| High | Confirmed defect | `src/generate_dataset.py:390-429`, `base_record()` | Hard negatives retained `scam_family`, contradicting `pattern_outcome: none`. All conversation stages were `identified`, so the documented `undetermined` state was unused. | Added `scenario_family`; `scam_family` now requires observable anchors. Early conversation stages are `undetermined`; only action-request stages are identified. |
| High | Confirmed defect | `src/generate_dataset.py:280`, `adversarial()` | Leetspeak and mixed-script mutation could alter the reserved `.invalid` hostname. | URL tokens are protected from lexical mutation; percent encoding is limited to the URL path. |
| Medium | Confirmed defect | `src/generate_dataset.py:709`, `generate()` | A failed regeneration could partially replace an existing release. | Generation now completes in an isolated sibling directory and atomically swaps the complete output, with rollback on promotion failure. |
| Medium | Confirmed defect | `src/generate_dataset.py:510`, `label_schedule()` | Independent rounding produced a negative class count for a four-record request. | Replaced with an exact largest-remainder allocator; tested for every size from 1 through 100 and the full release size. |
| Medium | Confirmed defect | `src/validate_dataset.py:65`, `validate_manifest_files()` | Manifest paths were not constrained to the dataset root and duplicate paths were accepted. | Rejects traversal, absolute, non-canonical, backslash and duplicate paths; verifies size and full SHA-256. |
| Medium | Confirmed defect | `src/validate_dataset.py:141-144`, `validate()` | Extra undeclared shards, including empty shards, could escape the previous count comparison. | Declared and physical shard inventories must match exactly. |
| Medium | Confirmed defect | `src/validate_dataset.py:49` and `:225` | Normalized-text IDs were trusted instead of recomputed, weakening leakage assertions. | Validator independently recomputes every normalized-text cluster ID. |
| Medium | Confirmed defect | `src/generate_dataset.py:186`, `load_anchor_payload()` | A missing anchor pack silently downgraded generation despite documentation claiming 18 enhanced languages. | The pack is mandatory and its structure, licence and review status are validated. |
| Medium | Confirmed defect | `src/generate_dataset.py:442` and `src/validate_dataset.py:153` | The distributed schema described only part of each record and allowed undeclared fields. | Schema now defines and requires every field, rejects additional properties and is reconciled with the validator contract. |
| Medium | Confirmed defect | `src/validate_dataset.py:265` and `:322` | Preview and quality-report contents were hashed but not reconciled with streamed records. | The validator now compares the preview with the first 500 records and recomputes all quality-report statistics. |
| Low | Confirmed defect | `RELEASE_NOTES.md`, v0.2.0 notes | The source register was described as “audited” without a recorded source-verification procedure. | Corrected to “documented research-source register.” |
| High | Confirmed defect | `src/generate_dataset.py`, `generate()` | A mistyped output path could replace any existing directory after generation completed. | Added a guarded output-target check that rejects filesystem roots, symlinks and nonempty directories without a recognized dataset manifest; added three regression tests. |

## Verification performed

- Python bytecode compilation: passed.
- Regression suite: 26 of 26 tests passed.
- Full deterministic regeneration: 1,500,000 records completed.
- Full streaming validation: passed.
- Unique IDs and exact texts: 1,500,000 each.
- Language–family coverage: 3,000 of 3,000 cells.
- Campaign, template, near-duplicate and normalized-text split leakage: zero.
- Live URLs: zero.
- Manifest SHA-256 and byte checks: passed for every distributed data file.
- Dependency check: passed; generator and validator use only the Python standard library.
- Secret and unsafe-execution scan: no exposed credentials, subprocess execution,
  dynamic evaluation, network client or unsafe deserialization found.
- Visible-artifact scan: no assistant transcripts, prompt fragments, placeholder
  citations or “as an AI” text found in the audited scope. This is not a claim
  about code authorship.
- NexVision Lab copyright, PolyForm Noncommercial 1.0.0 terms and SPDX identifier:
  preserved.

## Unresolved production blockers

1. **No real-world external validation.** Performance must be measured on an
   independently collected corpus separated by campaign, sender, domain and time.
2. **No native-language approval.** All 50 language packs remain `not_reviewed`;
   32 use only generic seed packs.
3. **No calibrated operational thresholds.** Per-language false-positive,
   false-negative, abstention and escalation thresholds have not been established.
4. **Synthetic distribution gap.** Template balance does not represent real scam
   prevalence, code-switching, dialects, typos or evolving campaigns.
5. **No release provenance from version control.** The supplied ZIP contained no
   Git history or signed build attestation; the archive and internal files are
   hashable, but commit-to-build traceability could not be assessed.
6. **Governance remains external to this repository.** Production use still needs
   dataset approval, change control, drift monitoring, incident handling and an
   analyst-review workflow.

These blockers do not prevent use as a controlled offline research, taxonomy and
regression-testing dataset. They do prevent evidence-based claims that a model
trained on this release is production validated.
