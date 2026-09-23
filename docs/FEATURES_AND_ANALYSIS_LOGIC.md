# Features and analysis logic

## Purpose and current boundary

NexVision ScamText Global v0.2.1 is an offline synthetic dataset generator and
integrity validator. It creates labelled research messages for training,
regression testing and evaluating future scam-message detection systems.

The repository does not yet contain a production classifier that accepts an
arbitrary SMS, WhatsApp message or direct message and returns a calibrated risk
score. Labels in this release are deterministic ground truth assigned during
synthetic generation. They are not model predictions.

## Feature catalogue

| Capability | Implemented behaviour |
|---|---|
| Scam taxonomy | 60 families grouped into 12 macro categories |
| Multi-axis description | Family, pretext, objective, sector, requested action and lure are separate fields |
| Pattern outcomes | `identified`, `undetermined` and `none` |
| Message classes | Scam, adversarial scam, benign, hard negative and conversation turn |
| Multilingual coverage | 50 language labels across 21 scripts |
| Localized anchors | Deeper category anchors for 18 languages; generic seeds for 32 |
| Channels | SMS, WhatsApp, Telegram, Facebook, Instagram and generic DM |
| Evasion simulation | Leetspeak, zero-width insertion, token splitting, percent encoding, mixed scripts and repeated punctuation |
| Conversation context | Contact, trust building, pretext, pressure and action-request stages |
| Benign-context control | Legitimate notices explicitly state that payment and credentials are not requested |
| Negation control | Awareness examples mention scam concepts while negating the harmful action |
| Leakage controls | Campaign, structural template, near-duplicate and normalized-text clusters |
| Safe examples | Reserved bracketed `.invalid` hosts, `hxxps`, synthetic brands and synthetic references |
| Reproducibility | Deterministic generation, versioned taxonomy and SHA-256 file manifest |
| Integrity validation | Streaming schema, semantics, safety, balance, hash and split checks |
| Failure safety | Transactional builds and guarded output-directory replacement |

## End-to-end generation pipeline

1. **Load governed inputs.** The generator requires the checked-in anchor pack,
   verifies its structure, licence, review status and expected 18-language
   cardinality, and builds the 60-family taxonomy and 50-language registry.
2. **Allocate classes.** A largest-remainder allocator converts the requested
   record count into exact non-negative class counts. The 1.5-million-record
   reference mix is 600,000 scam, 350,000 benign, 250,000 hard negative,
   200,000 adversarial scam and 100,000 conversation turns.
3. **Select the scenario.** Records rotate deterministically through language,
   family, channel, synthetic brand, payment method, lure, amount, deadline,
   URL path and one of 20 structural variants.
4. **Choose the language anchor.** An available category-specific anchor is
   selected for tier-A languages. Other languages use the taxonomy pretext plus
   localized core seed phrases and are flagged `generic_seed_only`.
5. **Render the message.** Components are reordered with one of ten orders and
   two separators. This produces 20 structural variants without embedding an
   identifying label in the message.
6. **Apply class logic.** Scam, benign, hard-negative and conversation templates
   expose different anchors and receive outcomes according to the rules below.
7. **Apply evasion when required.** Adversarial records receive one deterministic
   evasion mode. Defanged URLs are protected from lexical mutations.
8. **Create identifiers.** The generator derives record and cluster identifiers
   with truncated SHA-256 digests over stable, documented inputs.
9. **Write transactionally.** Metadata, preview and gzip JSONL shards are written
   in an isolated sibling directory. Only a complete build replaces an existing
   recognized dataset output.
10. **Produce evidence.** The release includes a schema, provenance file,
    quality report and manifest containing byte sizes and SHA-256 hashes.

## Label and pattern-decision logic

The key design rule is that a generating scenario is not automatically an
observable scam pattern. `scenario_family` describes how a synthetic example
was constructed. `scam_family` is exposed only when the rendered message has an
action anchor sufficient to identify the family.

| Record class or stage | Observable content | `pattern_outcome` | `scam_family` | `requested_action` |
|---|---|---|---|---|
| Scam | Urgency/pretext plus payment or verification action | `identified` | Family ID | Present |
| Adversarial scam | Same harmful structure with one evasion | `identified` | Family ID | Present |
| Benign | Legitimate notice plus explicit no-payment/no-secret wording | `none` | `null` | `null` |
| Hard negative | Awareness/training language that negates the action | `none` | `null` | `null` |
| Conversation: contact | Initial contact only | `undetermined` | `null` | `null` |
| Conversation: trust building | Trust or confidentiality language | `undetermined` | `null` | `null` |
| Conversation: pretext | Scenario pretext without the harmful request | `undetermined` | `null` | `null` |
| Conversation: pressure | Urgency/deadline without the harmful request | `undetermined` | `null` | `null` |
| Conversation: action request | Payment/action wording and defanged URL | `identified` | Family ID | Present |

This logic prevents two important false-label patterns:

- A warning such as “never transfer money” may mention a scam family but is a
  hard negative, not a scam message.
- Early grooming or contact may be suspicious but lacks enough observable
  evidence to name a family, so the correct result is `undetermined`.

## Scam taxonomy

Each macro category contains five families:

| Macro category | Families |
|---|---|
| Account and identity | Credential phishing; account suspension; identity/KYC theft; social-media takeover; SIM-swap pretext |
| Authority and coercion | Government impersonation; digital arrest; court/police threat; tax impersonation; immigration/visa |
| Financial services | Bank impersonation; safe-account transfer; advance-fee loan; refund/rebate; false debt collection |
| Investment and crypto | Investment; crypto wallet; token approval; illegal gambling; fake influencer endorsement |
| Work and business | Job/task; money mule; business payment diversion; education-fee impersonation; scholarship |
| Commerce and delivery | Parcel delivery; customs fee; marketplace buyer; e-commerce non-delivery; fake online shop |
| Personal relationships | Fake friend/new number; family emergency; romance; wrong-number grooming; dating verification |
| Rewards and advance fees | Prize/lottery; general advance fee; loyalty points; survey reward; gift card |
| Technology and subscriptions | Technical support; malware delivery; subscription refund; QR payment; deepfake impersonation |
| Property, travel and services | Rental; travel booking; ticketing; pet adoption; fake legal services |
| Health, charity and recovery | Healthcare/medical; insurance; charity; disaster donation; fraud recovery |
| Threat, billing and utilities | Blackmail/sextortion; utility disconnection; toll/parking/traffic fee; mobile top-up; premium-rate callback |

The generated `taxonomy.json` provides the stable family ID, name, macro
category, pretext, objective, impersonated sector and requested action for every
family.

## Multilingual logic

Every language entry records its language code, name, script, coverage tier,
seed method and native-review status.

- **Tier A:** 18 languages with deeper category-specific anchor packs.
- **Tier B:** 32 languages with localized core phrases and generic taxonomy
  pretexts.
- **Native review:** all 50 languages remain `not_reviewed` in v0.2.1.

Tier A means greater synthetic anchor depth; it does not mean that a native
speaker approved the language. International technical terms may remain in
messages, and each record carries quality flags describing this limitation.

## Adversarial transformations

| Mode | Transformation | Safety rule |
|---|---|---|
| `leetspeak` | Replaces selected Latin characters with digits | Defanged URL token is protected |
| `zero_width` | Inserts zero-width characters near spaces | Text remains valid Unicode |
| `split_tokens` | Spaces characters in selected trigger words | Only selected tokens are changed |
| `percent_encoding` | Encodes the synthetic URL path | Host remains reserved `.invalid` |
| `mixed_script` | Replaces selected Latin letters with Cyrillic/Greek confusables | Limited simulation, not full UTS #39 analysis |
| `repeated_punctuation` | Repeats or appends exclamation marks | No live link is introduced |

These records test robustness against obfuscation. They do not implement a
general-purpose Unicode-confusable detector.

## Split and leakage logic

Each language/family campaign rotates through 20 structural variants:

- variants 0–15 → training;
- variants 16–17 → development;
- variants 18–19 → test.

The split is derived from the structural variant. Complete related clusters are
therefore assigned to one split. Four identifiers are tracked:

| Identifier | Groups |
|---|---|
| `campaign_id` | Language, scam family and structural variant across related classes |
| `template_cluster_id` | Record class and structural variant |
| `near_duplicate_cluster_id` | Language, family, class and structural variant |
| `normalized_text_cluster_id` | Case-folded text after URL, reference, number and whitespace normalization |

The generator detects leakage while writing. The independent validator rebuilds
the mappings and fails if any cluster appears in more than one split.

## Streaming validation logic

The validator does not trust the generated manifest. It independently checks:

1. exactly 60 unique taxonomy families and 50 unique languages;
2. canonical relative manifest paths with no traversal, absolute paths,
   backslashes or duplicates;
3. declared versus physical shard inventory;
4. byte size and SHA-256 for every declared file;
5. complete schema fields and rejection of unexpected fields;
6. record, campaign and cluster identifier formats;
7. unique record IDs and unique exact message text;
8. message length, absence of live `http://` or `https://` URLs and reserved
   defanged host format;
9. language, quality-tier, provenance and licence consistency;
10. label/outcome/family/action semantic consistency;
11. independently recomputed normalized-text clusters and expected splits;
12. zero leakage across all four protected cluster types;
13. preview equality with the first 500 streamed records;
14. manifest counts, balance statistics, language-family coverage and quality
    report reconciliation; and
15. synthetic-only provenance, no-real-message and no-personal-data assertions.

Validation is fail-closed: the first inconsistency raises an error and the
release must not be treated as verified.

## Output artifacts

| Artifact | Purpose |
|---|---|
| `shards/*.jsonl.gz` | Compressed dataset records |
| `taxonomy.json` | Machine-readable scam taxonomy |
| `language_registry.json` | Language, script, tier and review metadata |
| `curated_anchor_packs.json` | Versioned localized anchor input |
| `schema.json` | Complete closed record schema |
| `preview.jsonl` | First 500 records for inspection |
| `provenance.json` | Source, safety, licence and generation declarations |
| `quality_report.json` | Balance, coverage, cluster and review statistics |
| `manifest.json` | Counts plus file sizes and SHA-256 hashes |

## What is not implemented in v0.2.1

- Live-message classification or calibrated scam probability
- Character/word statistical classifier or trained ML model
- Full UTS #39 confusable detection
- Public-suffix domain parsing or domain reputation analysis
- Downloadable threat-feed ingestion
- Screenshot OCR or QR-code decoding
- Sender reputation, phone-number intelligence or conversation import
- HTML/PDF analyst reports for arbitrary submitted messages
- Authentication, rate limiting, analyst workflow or OSINT360 integration
- Real-world external validation and per-language operational thresholds

These are product-roadmap capabilities, not hidden or partially operational
features in this dataset release.

## Extension points

To add a family, update `FAMILY_SPECS` and `FAMILY_ANCHOR_KEYS`, then extend the
tests; generation deliberately fails if those sets diverge. To add a language,
add a unique `LANGUAGE_SEEDS` entry and, if applicable, a governed anchor pack.
Record any native review separately from coverage tier. Every change should
regenerate a representative dataset, pass the full validator and receive
campaign-separated external validation before production claims are made.
