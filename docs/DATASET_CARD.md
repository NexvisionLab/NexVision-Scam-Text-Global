# Dataset card

## Intended uses

- Offline scam-message rule development
- Multiclass taxonomy prototyping
- Robustness tests for obfuscation, homoglyphs and spacing attacks
- Benign-context and negation regression testing
- Conversation-stage research
- Pre-training or curriculum data before real-world validation

## Out-of-scope uses

- Treating a score as proof that a person committed fraud
- Automatic blocking without appeal or review
- Claiming per-language operational performance from synthetic data
- Sender attribution, geolocation or criminal identification
- Reconstructing real credentials, URLs, identities or financial details

## Principal limitations

1. All v0.2.1 records are synthetic.
2. Language quality is unequal and no language is fully native-reviewed.
3. Templates cannot reproduce the full distribution of real scam campaigns.
4. Counts do not imply prevalence; the release is deliberately balanced.
5. Many non-English records contain international brand or English technical
   tokens, reflecting common code-switching but not purely monolingual usage.
6. Conversation records are short staged simulations, not victim transcripts.

## Required validation before deployment

- Native-speaker review for every deployed language and locale
- Independent real-world benign and malicious corpora
- Campaign, sender, domain and time-separated evaluation
- Per-language calibration, false-positive and false-negative thresholds
- Drift monitoring and analyst-review feedback
- Licence, consent, PII and ethics review for any added real messages
