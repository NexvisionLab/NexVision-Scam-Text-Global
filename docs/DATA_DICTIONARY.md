# Data dictionary

Every generated record is a JSON object with exactly the 36 fields below. The
generated `schema.json` is the machine-readable authority and is closed
(`additionalProperties: false`); a test fails if this page and the schema
disagree.

| Field group | Field | Type | Meaning |
|---|---|---|---|
| Identity | `record_id` | string | Stable identifier, `NVDS-` plus 20 hex characters |
| Content | `text` | string | The synthetic message (1–1,200 characters) |
| Content | `channel` | enum | `sms`, `whatsapp`, `telegram`, `facebook`, `instagram` or `dm` |
| Classification | `label` | enum | `scam`, `adversarial_scam`, `benign`, `hard_negative` or `conversation_turn` |
| Classification | `pattern_outcome` | enum | `identified`, `undetermined` or `none` |
| Classification | `scam_family` | string or null | Family ID, set only when the message itself carries enough anchors to name it |
| Classification | `scenario_family` | string or null | Family used to construct the example; may be set for hard negatives and early conversation turns |
| Classification | `macro_category` | string or null | One of the 12 macro categories, set only with `scam_family` |
| Language | `language` | string | Language code, e.g. `en`, `hi` |
| Language | `language_name` | string | English name of the language |
| Language | `script` | string | ISO 15924 script code, e.g. `Latn`, `Deva` |
| Language | `language_form` | string | Whether a curated anchor phrase or only a generic seed was used |
| Language | `language_quality_tier` | enum | `A` (curated anchor pack) or `B` (generic seed only) |
| Language | `native_review_status` | enum | `not_reviewed`, `sample_reviewed` or `fully_reviewed` |
| Anchors | `pretext` | string or null | The pretext phrase used; `null` for benign records |
| Anchors | `requested_action` | string or null | Action the message asks for; set only when an action anchor is present |
| Anchors | `objective` | string or null | The scam's goal; set only when an action anchor is present |
| Anchors | `impersonated_sector` | string | Sector the message pretends to come from |
| Anchors | `payment_method` | string or null | Payment channel named in the message, when an action is requested |
| Anchors | `lure` | string or null | Persuasion lure, for scams and for pressure or action-request turns |
| Conversation | `conversation_stage` | enum | `contact`, `trust_building`, `pretext`, `pressure`, `action_request`, `awareness` or `legitimate_notice` |
| Robustness | `evasion_types` | array of string | Evasion applied (empty unless `adversarial_scam`) |
| Robustness | `contains_defanged_url` | boolean | Whether the text contains an `hxxps://` `.invalid` link |
| Splitting | `split` | enum | `train`, `development` or `test` |
| Splitting | `campaign_id` | string | `CMP-` plus 16 hex characters; a language, family and structural variant |
| Splitting | `template_cluster_id` | string | `TPL-<label>-<variant>` structural template group |
| Splitting | `near_duplicate_cluster_id` | string | `ND-` plus 16 hex characters |
| Splitting | `normalized_text_cluster_id` | string | `TXT-` plus 16 hex characters over URL-, number- and reference-normalized text |
| Splitting | `template_id` | string | Template slot, `<label>-<000..119>` |
| Provenance | `source_type` | enum | `synthetic` for every v0.2.1 record |
| Provenance | `generation_method` | string | Generator version |
| Provenance | `taxonomy_version` | string | Taxonomy version used |
| Provenance | `licence` | string | `PolyForm-Noncommercial-1.0.0` |
| Quality | `quality_flags` | array of string | Language and synthetic-origin limitations, e.g. `synthetic`, `native_review_pending` |
| Safety | `pii_present` | boolean | Always `false` |
| Safety | `safety_status` | string | Always `defanged` |

`scam_family` is populated only when observable anchors support a family.
`scenario_family` records the synthetic scenario and may be present for a hard
negative or early conversation turn even when the observed pattern is `none` or
`undetermined`.
