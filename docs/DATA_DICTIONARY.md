# Data dictionary

Every generated record is a JSON object. The generated `schema.json` is the
machine-readable authority; this page summarizes the fields.

| Field group | Fields | Meaning |
|---|---|---|
| Identity | `id`, `version` | Stable record identifier and release version |
| Content | `text`, `language`, `script`, `locale_hint` | Synthetic message and language metadata |
| Classification | `label`, `pattern_outcome`, `scam_family`, `scenario_family`, `macro_category` | Observed label and generating scenario |
| Anchors | `lure`, `objective`, `sector`, `requested_action`, `urgency`, `authority_claim` | Explainable message signals |
| Conversation | `conversation_id`, `conversation_stage`, `turn_index` | Optional staged-conversation context |
| Robustness | `adversarial`, `evasion_type`, `contains_defanged_url` | Obfuscation and URL flags |
| Splitting | `split`, `campaign_id`, `template_cluster_id`, `near_duplicate_cluster_id`, `normalized_text_cluster_id` | Leakage-resistant grouping |
| Provenance | `source_type`, `generation_method`, `taxonomy_version`, `licence` | Origin and version information |
| Quality | `language_form`, `language_quality_tier`, `native_review_status`, `quality_flags` | Language limitations and review state |
| Safety | `pii_present`, `safety_status` | Synthetic privacy and defanging assertions |

`scam_family` is populated only when observable anchors support a family.
`scenario_family` records the synthetic scenario and may be present for a hard
negative or early conversation turn even when the observed pattern is `none` or
`undetermined`.

