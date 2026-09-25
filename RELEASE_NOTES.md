# Release notes

## Unreleased - Windows compatibility and documentation fixes

Generated data is unchanged for the same arguments; only manifest path
separators differ on Windows, where they were previously wrong.

- Fixes `OSError: [Errno 9] Bad file descriptor` on Windows: shard `fsync` now
  opens the file read-write (Windows rejects a read-only descriptor).
- Writes manifest paths with POSIX separators and compares shard inventories the
  same way. On Windows the manifest previously contained backslashes, which the
  validator correctly rejected, so no build could validate there.
- The symbolic-link test skips when the OS does not permit creating links.
- Adds a warning when a build is too small to contain development or test
  records (they only begin after 48,000 and 54,000 records).
- Rewrites `docs/DATA_DICTIONARY.md` to match the real 36-field schema (it had
  documented ten fields that do not exist) and adds a test that keeps them in sync.
- Corrects the repository name in `CITATION.cff` and the release report, and the
  reproduction command in `QA_v0.2.1.md` (the generator refuses to overwrite a
  non-empty unmanaged directory such as `data/`).
- Adds a cross-platform GitHub Actions workflow (Linux, Windows, macOS).

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
