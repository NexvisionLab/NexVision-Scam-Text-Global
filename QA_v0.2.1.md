# Quality assurance — v0.2.1

Validation date: 2026-09-23  
Release status: passed for controlled research use; operational validation required

## Release checks

| Check | Result |
|---|---:|
| Records | 1,500,000 |
| Unique record IDs | 1,500,000 |
| Unique exact texts | 1,500,000 |
| Languages | 50 |
| Scripts | 21 |
| Scam families | 60 |
| Language–family cells | 3,000 / 3,000 |
| Campaign clusters | 60,000 |
| Structural template clusters | 100 |
| Near-duplicate clusters | 300,000 |
| Normalized-text clusters | 1,138,063 |
| Live URLs detected | 0 |
| Campaign split leakage | 0 |
| Template split leakage | 0 |
| Near-duplicate split leakage | 0 |
| Normalized-text split leakage | 0 |
| Regression tests | 26 passed |
| Python bytecode compilation | Passed |
| Dependency consistency | Passed; standard library only |

## Split, label and outcome balance

- Train: 1,200,000 records (80%)
- Development: 150,000 records (10%)
- Test: 150,000 records (10%)
- Scam: 600,000
- Benign: 350,000
- Hard negative: 250,000
- Adversarial scam: 200,000
- Conversation turn: 100,000
- Pattern identified: 820,000
- Pattern undetermined: 80,000
- No pattern supported: 600,000
- Every language has 30,000 records with the same label distribution.

## Language-quality controls

- 18 languages include deeper category-specific anchor packs and are tier A.
- 32 languages use smaller generic seed packs and are tier B.
- Every row records its language form, quality tier, quality flags and review status.
- No language is marked as native-reviewed. Tier A indicates greater synthetic
  semantic depth, not professional translation approval.

## Integrity and safety controls

- Generation occurs in an isolated sibling directory and promotes the complete
  release transactionally.
- Generation refuses filesystem roots, symbolic-link outputs and nonempty
  unmanaged directories.
- The validator rejects unsafe manifest paths, duplicate paths, undeclared
  shards, omitted metadata, malformed identifiers and hash or byte mismatches.
- Normalized-text cluster IDs are recomputed from record text.
- Label, pattern-outcome, scenario-family and action-anchor semantics are checked.
- All generated URL hosts are reserved bracketed `.invalid` examples; live URLs
  are rejected.

## Reproduction commands

```bash
python src/generate_dataset.py --output data --records 1500000 --shard-size 100000
python src/validate_dataset.py data
python -m unittest discover -s tests -v
```

## Limitations

This release is entirely synthetic. It is suitable for taxonomy development,
offline regression testing and pre-training experiments, but it does not
measure real-world accuracy. Operational use requires independently collected
data, campaign/sender/domain/time-separated external evaluation, native-speaker
review, per-language calibration, false-positive analysis and drift monitoring.
