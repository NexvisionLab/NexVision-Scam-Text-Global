# Reproducibility

## Reference environment

- Python 3.11 or newer
- UTF-8 filesystem
- No third-party packages
- Generator version `deterministic-template-0.2.1`
- Taxonomy version `2026.09.23-3`

## Rebuild

From the repository root:

```bash
python -m unittest discover -s tests -v
python src/generate_dataset.py --output build/v0.2.1 --records 1500000 --shard-size 100000
python src/validate_dataset.py build/v0.2.1
```

The output manifest records record counts, cluster counts, split statistics,
byte sizes and SHA-256 hashes for every data file. Gzip output is deterministic
for a fixed Python implementation and generator version because timestamps are
not embedded by the generator.

## Verification boundary

The validator verifies the selected output directory. It does not attest to the
Git commit, Python interpreter binary or operating system. A production release
process should add a signed tag, a build attestation and an independently stored
artifact digest.

