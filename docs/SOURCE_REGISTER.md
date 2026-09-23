# Source and evidence register

No third-party message text is redistributed in v0.2.1. The following sources
informed taxonomy design or were evaluated as candidates for a future,
separately licensed real-message layer.

| Source | Reported scope | v0.2.1 use | Reason |
|---|---:|---|---|
| Singapore ScamShield and SPF scam briefs | Singapore scam types and examples | Taxonomy research only | Public guidance; message reuse requires item-level review |
| FBI IC3 annual reports | Internet-crime categories and trends | Taxonomy research only | Aggregated reporting, not a redistributable message corpus |
| FTC Consumer Sentinel Data Book | Fraud categories and aggregate reports | Taxonomy research only | Underlying complaint data is restricted |
| INTERPOL social-engineering guidance | Global scam families | Taxonomy research only | Guidance, not training data |
| Australian Scamwatch | Scam types and warning signs | Taxonomy research only | Examples require provenance and reuse review |
| UCI SMS Spam Collection | 5,574 spam/ham messages | Excluded | Older binary corpus; licence and overlap audit required |
| SmishTank Dataset I | Approximately 1,090 smishing samples | Excluded | Requires record-level licence, PII and duplication review |
| IMC 2025 Smishing Dataset | 33,869 messages, 66 detected languages | Excluded | CC BY 4.0 candidate; retain as independent evaluation until audited |
| Super SMS Dataset | Reported 153,551 aggregated messages | Excluded | Aggregates multiple sources; source-level rights and overlap require audit |
| FLORES-200 | 200-language translation benchmark | Language research only | General-domain evaluation data, not scam-labelled messages |
| MADLAD-400 | General-domain corpus spanning 419 languages | Language research only | Not scam-labelled and unsuitable as direct validation data |

Primary references:

- https://www.scamshield.gov.sg/i-want-protection-from-scams/
- https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- https://www.ftc.gov/reports/consumer-sentinel-network-data-book-2024
- https://www.interpol.int/Crimes/Financial-crime/Social-engineering-scams
- https://www.scamwatch.gov.au/types-of-scams
- https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- https://arxiv.org/abs/2402.18430
- https://github.com/reportsmishing/Smishing-Dataset-IMC25
- https://github.com/smspamresearch/spstudy
- https://github.com/facebookresearch/flores/tree/main/flores200
- https://arxiv.org/abs/2309.04662

Before any candidate is imported, NexVision must record its original licence,
retrieval date, source record ID, consent basis where applicable, PII treatment,
deduplication result and permitted redistribution status.
