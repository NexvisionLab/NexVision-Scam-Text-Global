# Release notes

## 0.2.1 — integrity-audited maintenance release

- Corrects language quality tier A to the 18 languages that actually contain
  expanded anchor packs; the remaining 32 are tier B.
- Separates an identified `scam_family` from the synthetic `scenario_family`
  used for hard negatives and early conversation stages.
- Uses `undetermined` for conversation stages that lack an action anchor.
- Preserves the reserved bracketed `.invalid` host during adversarial mutation.
- Makes output-directory replacement transactional and preserves a prior valid
  release when generation fails.
- Replaces independent rounding with exact non-negative class allocation for
  every supported record count.
- Rejects unsafe or duplicate manifest paths, missing metadata, undeclared
  shards, malformed identifiers, semantic label conflicts, non-reserved URL
  hosts and incorrect normalized-text clusters.
- Expands defect-specific regression coverage and records remaining deployment
  blockers in the audit report.
- Refuses filesystem roots, symbolic-link outputs and nonempty unmanaged output
  directories to prevent accidental replacement of unrelated data.

## 0.2.0 — governed multilingual research release

- Produces 1,500,000 deterministic synthetic records.
- Covers 50 language labels, 21 scripts and 60 scam families.
- Adds campaign, structural-template, near-duplicate and normalized-text
  cluster identifiers.
- Holds complete cluster variants out of training with an 80/10/10 split.
- Adds a complete 3,000-cell language-by-family coverage requirement.
- Adds exact-text duplicate detection, unique-ID validation and full file hashes.
- Adds language balance, family balance and label-by-language statistics.
- Adds deeper category-specific anchor phrases for 18 languages while clearly
  identifying the remaining 32 seed-only language packs.
- Records native-review status, language quality tier and quality flags on every row.
- Keeps all URLs defanged and contains no real personal information.
- Includes a documented research-source register without redistributing third-party text.
- Uses the PolyForm Noncommercial 1.0.0 licence with NexVision Lab ownership.

## 0.1.0 — internal foundation

- Initial 50-language deterministic generator and 60-family taxonomy.
- Superseded before public release after campaign clusters were found to be too granular.
