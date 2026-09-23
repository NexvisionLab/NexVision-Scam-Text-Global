# Security policy

## Supported version

Security fixes are applied to the latest published release. Version 0.2.1 is a
research release and is not approved for operational enforcement.

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory workflow. Open the
repository, choose **Security**, then **Advisories**, and select **Report a
vulnerability**. Do not disclose an unpatched vulnerability in a public issue.

Include the affected version, a minimal reproduction, expected impact and any
suggested remediation. Remove credentials, tokens, personal identifiers and
real victim messages before submission.

## Data-safety reports

If a generated record appears to contain personal information, a reachable URL
or other unsafe content, report only the record ID and release version through
the private advisory workflow. Do not paste the sensitive value publicly.

## Security model

The generator and validator are offline command-line tools. They do not use
network clients, subprocesses, dynamic evaluation, unsafe deserialization or
third-party runtime dependencies. Output paths are local, and the generator
uses transactional directory replacement. The validator constrains manifest
paths to the selected dataset root and verifies file sizes and SHA-256 hashes.

