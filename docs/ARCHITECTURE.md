# Architecture

## Components

1. `curated_anchor_packs.json` supplies offline localized anchor phrases.
2. `generate_dataset.py` combines taxonomy, language seeds, labels and
   deterministic variants, then writes an isolated staging directory.
3. The generator computes metadata, quality statistics and SHA-256 hashes,
   then atomically promotes the completed directory.
4. `validate_dataset.py` streams every shard and independently verifies schema,
   semantics, hashes, safe paths, reserved URLs, counts and split isolation.
5. `test_dataset.py` exercises generation, failure recovery and validator
   rejection paths.

## Trust boundaries

- The checked-in anchor pack is trusted only after source, licence and native-
  review metadata are checked.
- The output directory is untrusted until the validator passes.
- A passing synthetic build establishes internal consistency, not real-world
  model performance.
- Any future external threat feed or real-message corpus is a separate,
  untrusted input requiring licence, privacy, malware and provenance review.

## Offline guarantee

The runtime code imports only Python standard-library modules and contains no
network client. Generation does not download models, feeds or language packs.
Reproducibility therefore depends on the repository contents, Python version,
command arguments and the documented generator version.

