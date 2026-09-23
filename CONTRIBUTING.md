# Contributing

Contributions are welcome for defects, tests, documentation, taxonomy coverage
and language quality. This project is source-available; contributions are
accepted under the repository licence.

## Before opening a change

- Do not commit real scam messages, victim data, credentials, phone numbers,
  email addresses, account identifiers or reachable malicious links.
- Use synthetic placeholders and reserved `.invalid` domains.
- Document the source, licence and review status of every language resource.
- Do not mark a language as native-reviewed without a recorded review process.
- Add a regression test for every corrected defect.
- Preserve campaign and cluster separation across dataset splits.

## Local verification

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
python src/generate_dataset.py --output build/contribution-check --records 15000 --shard-size 5000
python src/validate_dataset.py build/contribution-check
```

The complete 1,500,000-record build should also be regenerated and validated
before a tagged dataset release.

## Pull requests

Explain the problem, the evidence for the change, affected languages or scam
families, test results and any remaining limitations. Keep generated bulk
shards out of commits; they belong in versioned release artifacts.

