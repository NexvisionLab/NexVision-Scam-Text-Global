#!/usr/bin/env python3
"""Streaming integrity validator for a generated NexVision dataset release."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


LIVE_URL = re.compile(r"(?i)\bhttps?://")
RECORD_ID = re.compile(r"^NVDS-[0-9a-f]{20}$")
CAMPAIGN_ID = re.compile(r"^CMP-[0-9a-f]{16}$")
TEMPLATE_CLUSTER_ID = re.compile(r"^TPL-(scam|benign|hard_negative|adversarial_scam|conversation_turn)-(0[0-9]|1[0-9])$")
NEAR_DUPLICATE_ID = re.compile(r"^ND-[0-9a-f]{16}$")
NORMALIZED_TEXT_ID = re.compile(r"^TXT-[0-9a-f]{16}$")
DEFANGED_HOST = re.compile(r"(?i)\bhxxps://([^\s/]+)")
LABELS = {"scam", "benign", "hard_negative", "adversarial_scam", "conversation_turn"}
OUTCOMES = {"identified", "undetermined", "none"}
LICENCE = "PolyForm-Noncommercial-1.0.0"
REQUIRED_METADATA = {
    "taxonomy.json", "language_registry.json", "schema.json", "provenance.json",
    "quality_report.json", "curated_anchor_packs.json", "preview.jsonl",
}
REQUIRED = {
    "record_id", "text", "label", "pattern_outcome", "language", "script",
    "channel", "campaign_id", "template_cluster_id", "near_duplicate_cluster_id",
    "normalized_text_cluster_id", "split", "source_type", "generation_method",
    "taxonomy_version", "native_review_status", "pii_present", "safety_status",
    "scam_family", "scenario_family", "conversation_stage", "requested_action",
    "contains_defanged_url", "licence", "quality_flags", "language_quality_tier",
    "macro_category", "language_name", "language_form", "pretext", "objective",
    "impersonated_sector", "payment_method", "lure", "evasion_types", "template_id",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def expected_normalized_cluster(text: str) -> str:
    value = text.casefold()
    value = re.sub(r"hxxps://\S+", "<url>", value)
    value = re.sub(r"\bnv-[0-9-]+\b", "<reference>", value)
    value = re.sub(r"\b\d+(?:[.:]\d+)?\b", "<number>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return "TXT-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def expected_split(template_cluster_id: str) -> str:
    if not isinstance(template_cluster_id, str) or not TEMPLATE_CLUSTER_ID.fullmatch(template_cluster_id):
        raise ValueError(f"invalid template cluster ID: {template_cluster_id!r}")
    variant = int(template_cluster_id.rsplit("-", 1)[1])
    return "train" if variant < 16 else "development" if variant < 18 else "test"


def validate_manifest_files(root: Path, manifest: dict) -> set[str]:
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest files must be a non-empty list")
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("manifest file entry must be an object")
        name = entry.get("path")
        if not isinstance(name, str) or not name or "\\" in name:
            raise ValueError(f"invalid manifest path: {name!r}")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
            raise ValueError(f"unsafe manifest path: {name!r}")
        if name in names:
            raise ValueError(f"duplicate manifest path: {name}")
        names.add(name)
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError(f"manifest path escapes dataset root: {name}")
        size = entry.get("bytes")
        expected_hash = entry.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"invalid manifest byte count: {name}")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ValueError(f"invalid manifest SHA-256: {name}")
        if not path.is_file() or path.stat().st_size != size or sha256(path) != expected_hash:
            raise ValueError(f"file integrity failure: {name}")
    return names


def validate_semantics(row: dict, record_id: str) -> None:
    label = row["label"]
    outcome = row["pattern_outcome"]
    scam_family = row["scam_family"]
    scenario_family = row["scenario_family"]
    action = row["requested_action"]
    stage = row["conversation_stage"]
    if label in {"scam", "adversarial_scam"}:
        valid = (stage == "action_request" and outcome == "identified" and
                 scam_family == scenario_family and isinstance(action, str))
    elif label == "benign":
        valid = (stage == "legitimate_notice" and outcome == "none" and
                 scam_family is None and scenario_family is None and action is None)
    elif label == "hard_negative":
        valid = (stage == "awareness" and outcome == "none" and scam_family is None and
                 scenario_family is not None and action is None)
    elif stage == "action_request":
        valid = outcome == "identified" and scam_family == scenario_family and isinstance(action, str)
    else:
        valid = (stage in {"contact", "trust_building", "pretext", "pressure"} and
                 outcome == "undetermined" and scam_family is None and
                 scenario_family is not None and action is None)
    if not valid:
        raise ValueError(f"label/outcome semantic mismatch at {record_id}")


def validate(root: Path) -> dict:
    root = root.resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    taxonomy = json.loads((root / "taxonomy.json").read_text(encoding="utf-8"))
    languages = json.loads((root / "language_registry.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(taxonomy, list) or not isinstance(languages, list):
        raise ValueError("manifest, taxonomy and language registry must have valid top-level types")
    family_ids = {row["id"] for row in taxonomy}
    language_map = {row["code"]: row for row in languages}
    language_ids = set(language_map)
    if len(taxonomy) != 60 or len(family_ids) != 60:
        raise ValueError("taxonomy must contain 60 unique families")
    if len(languages) != 50 or len(language_ids) != 50:
        raise ValueError("registry must contain 50 unique languages")

    file_names = validate_manifest_files(root, manifest)
    if not REQUIRED_METADATA.issubset(file_names):
        missing = sorted(REQUIRED_METADATA - file_names)
        raise ValueError(f"manifest omits required metadata files: {missing}")
    declared_shards = {name for name in file_names if name.startswith("shards/") and name.endswith(".jsonl.gz")}
    actual_shards = {str(path.relative_to(root)) for path in (root / "shards").glob("*.jsonl.gz")}
    if not declared_shards or declared_shards != actual_shards:
        raise ValueError("manifest shard inventory does not match the release directory")

    provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    quality_report = json.loads((root / "quality_report.json").read_text(encoding="utf-8"))
    anchor_packs = json.loads((root / "curated_anchor_packs.json").read_text(encoding="utf-8"))
    record_schema = json.loads((root / "schema.json").read_text(encoding="utf-8"))
    if manifest.get("version") != provenance.get("version") or manifest.get("version") != quality_report.get("version"):
        raise ValueError("release version mismatch across manifest, provenance and quality report")
    if set(record_schema.get("required", [])) != REQUIRED or record_schema.get("additionalProperties") is not False:
        raise ValueError("record schema does not match the validator field contract")
    anchor_languages = anchor_packs.get("languages")
    if not isinstance(anchor_languages, dict):
        raise ValueError("anchor pack languages must be an object")
    for code, language in language_map.items():
        expected_tier = "A" if code in anchor_languages else "B"
        expected_method = "curated_anchor_pack" if code in anchor_languages else "generic_seed_only"
        if language.get("coverage_tier") != expected_tier or language.get("seed_method") != expected_method:
            raise ValueError(f"language quality metadata mismatch for {code}")

    ids: set[str] = set()
    text_hashes: set[bytes] = set()
    cluster_splits = {field: {} for field in (
        "campaign_id", "template_cluster_id", "near_duplicate_cluster_id", "normalized_text_cluster_id"
    )}
    labels, outcomes, langs, families, splits = Counter(), Counter(), Counter(), Counter(), Counter()
    label_language_counts = Counter()
    language_family_pairs = set()
    preview_rows: list[dict] = []
    records = 0
    taxonomy_versions = {row.get("version") for row in taxonomy}
    if len(taxonomy_versions) != 1 or None in taxonomy_versions:
        raise ValueError("taxonomy must contain one non-empty version")
    taxonomy_version = next(iter(taxonomy_versions))
    for shard_name in sorted(declared_shards):
        shard = root / shard_name
        with gzip.open(shard, "rt", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{shard.name}:{line_number} record must be an object")
                missing = REQUIRED - row.keys()
                if missing:
                    raise ValueError(f"{shard.name}:{line_number} missing {sorted(missing)}")
                unexpected = row.keys() - REQUIRED
                if unexpected:
                    raise ValueError(f"{shard.name}:{line_number} unexpected {sorted(unexpected)}")
                record_id = row["record_id"]
                if not isinstance(record_id, str) or not RECORD_ID.fullmatch(record_id):
                    raise ValueError(f"invalid record_id at {shard.name}:{line_number}")
                if record_id in ids:
                    raise ValueError(f"duplicate record_id {record_id}")
                ids.add(record_id)
                text = row["text"]
                if not isinstance(text, str):
                    raise ValueError(f"text is not a string at {record_id}")
                text_hash = hashlib.sha256(text.encode("utf-8")).digest()
                if text_hash in text_hashes:
                    raise ValueError(f"duplicate exact text at {record_id}")
                text_hashes.add(text_hash)
                if not text or len(text) > 1200 or LIVE_URL.search(text):
                    raise ValueError(f"unsafe or invalid text at {record_id}")
                if row["label"] not in LABELS or row["pattern_outcome"] not in OUTCOMES:
                    raise ValueError(f"unknown label or pattern outcome at {record_id}")
                if row["language"] not in language_ids:
                    raise ValueError(f"unknown language at {record_id}")
                language = language_map[row["language"]]
                if (row["script"] != language["script"] or
                        row["native_review_status"] != language["native_review_status"] or
                        row["language_quality_tier"] != language["coverage_tier"]):
                    raise ValueError(f"language metadata mismatch at {record_id}")
                if row["scam_family"] is not None and row["scam_family"] not in family_ids:
                    raise ValueError(f"unknown family at {record_id}")
                if row["scenario_family"] is not None and row["scenario_family"] not in family_ids:
                    raise ValueError(f"unknown scenario family at {record_id}")
                if (not isinstance(row["campaign_id"], str) or not CAMPAIGN_ID.fullmatch(row["campaign_id"]) or
                        not isinstance(row["near_duplicate_cluster_id"], str) or
                        not NEAR_DUPLICATE_ID.fullmatch(row["near_duplicate_cluster_id"]) or
                        not isinstance(row["normalized_text_cluster_id"], str) or
                        not NORMALIZED_TEXT_ID.fullmatch(row["normalized_text_cluster_id"])):
                    raise ValueError(f"invalid cluster identifier at {record_id}")
                if row["normalized_text_cluster_id"] != expected_normalized_cluster(text):
                    raise ValueError(f"normalized-text cluster mismatch at {record_id}")
                defanged_hosts = DEFANGED_HOST.findall(text)
                if any(not re.fullmatch(r"example-\d+\[\.\]invalid", host) for host in defanged_hosts):
                    raise ValueError(f"non-reserved defanged URL host at {record_id}")
                if row["split"] != expected_split(row["template_cluster_id"]):
                    raise ValueError(f"template split mismatch at {record_id}")
                if not row["template_cluster_id"].startswith(f"TPL-{row['label']}-"):
                    raise ValueError(f"template label mismatch at {record_id}")
                for field, mapping in cluster_splits.items():
                    previous = mapping.setdefault(row[field], row["split"])
                    if previous != row["split"]:
                        raise ValueError(f"{field} split leakage at {record_id}")
                if row["pii_present"] is not False or row["safety_status"] != "defanged":
                    raise ValueError(f"privacy/safety failure at {record_id}")
                if (row["source_type"] != "synthetic" or row["taxonomy_version"] != taxonomy_version or
                        row["licence"] != LICENCE or not isinstance(row["generation_method"], str) or
                        not row["generation_method"] or not isinstance(row["quality_flags"], list)):
                    raise ValueError(f"provenance failure at {record_id}")
                if row["contains_defanged_url"] != ("hxxps://" in text):
                    raise ValueError(f"defanged URL flag mismatch at {record_id}")
                validate_semantics(row, record_id)
                labels[row["label"]] += 1
                outcomes[row["pattern_outcome"]] += 1
                langs[row["language"]] += 1
                label_language_counts[(row["language"], row["label"])] += 1
                splits[row["split"]] += 1
                if row["scenario_family"]:
                    families[row["scenario_family"]] += 1
                    language_family_pairs.add((row["language"], row["scenario_family"]))
                if records < 500:
                    preview_rows.append(row)
                records += 1

    stored_preview = []
    with (root / "preview.jsonl").open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line_number > 500:
                raise ValueError("preview contains more than 500 records")
            stored_preview.append(json.loads(line))
    if stored_preview != preview_rows:
        raise ValueError("preview does not match the first generated records")

    actual = {
        "records": records, "label_counts": dict(labels), "pattern_outcome_counts": dict(outcomes),
        "language_counts": dict(langs),
        "family_counts": dict(families), "split_counts": dict(splits),
    }
    for key in actual:
        if actual[key] != manifest[key]:
            raise ValueError(f"manifest mismatch for {key}")
    cluster_counts = {
        "campaigns": len(cluster_splits["campaign_id"]),
        "template_clusters": len(cluster_splits["template_cluster_id"]),
        "near_duplicate_clusters": len(cluster_splits["near_duplicate_cluster_id"]),
        "normalized_text_clusters": len(cluster_splits["normalized_text_cluster_id"]),
    }
    for key, value in cluster_counts.items():
        if manifest.get(key) != value:
            raise ValueError(f"manifest mismatch for {key}")
    if (manifest.get("taxonomy_families") != len(family_ids) or
            manifest.get("languages") != len(language_ids) or
            manifest.get("scripts") != len({row["script"] for row in languages})):
        raise ValueError("manifest taxonomy, language or script count mismatch")
    observed_pairs = len(language_family_pairs)
    expected_pairs = len(language_ids) * len(family_ids)
    if manifest.get("language_family_pairs") != observed_pairs:
        raise ValueError("manifest mismatch for language-family pairs")
    if manifest.get("language_family_pairs_expected") != expected_pairs:
        raise ValueError("manifest mismatch for expected language-family pairs")
    coverage_complete = observed_pairs == expected_pairs
    if manifest.get("language_family_coverage_complete") is not coverage_complete:
        raise ValueError("manifest mismatch for language-family coverage status")
    if coverage_complete and set(families) != family_ids:
        raise ValueError("complete coverage claimed without every taxonomy family")

    expected_label_language = {
        code: {label: label_language_counts[(code, label)] for label in manifest["label_counts"]}
        for code in sorted(language_ids)
    }
    expected_quality = {
        "records": records,
        "language_balance": {"minimum": min(langs.values()), "maximum": max(langs.values())},
        "family_balance": {"minimum": min(families.values()), "maximum": max(families.values())},
        "language_family_pairs_observed": observed_pairs,
        "language_family_pairs_expected": expected_pairs,
        "campaign_clusters": cluster_counts["campaigns"],
        "template_clusters": cluster_counts["template_clusters"],
        "near_duplicate_clusters": cluster_counts["near_duplicate_clusters"],
        "normalized_text_clusters": cluster_counts["normalized_text_clusters"],
        "native_reviewed_languages": 0,
        "synthetic_fraction": 1.0,
        "curated_anchor_pack_languages": len(anchor_languages),
        "generic_seed_only_languages": len(language_ids) - len(anchor_languages),
        "label_language_counts": expected_label_language,
    }
    for key, value in expected_quality.items():
        if quality_report.get(key) != value:
            raise ValueError(f"quality report mismatch for {key}")
    if any(quality_report.get(key) != 0 for key in (
        "campaign_split_leakage", "template_split_leakage",
        "near_duplicate_split_leakage", "normalized_text_split_leakage",
    )):
        raise ValueError("quality report contains a non-zero leakage result")
    if (provenance.get("source_types") != {"synthetic": records} or
            provenance.get("contains_real_messages") is not False or
            provenance.get("contains_personal_data") is not False or
            provenance.get("offline_generation") is not True or
            provenance.get("runtime_api_calls") is not False or
            provenance.get("licence") != LICENCE):
        raise ValueError("provenance metadata mismatch")
    return {"status": "passed", "records": records, "languages": len(langs),
            "families": len(families), "language_family_pairs": observed_pairs,
            "unique_ids": len(ids), "unique_texts": len(text_hashes), "live_urls": 0,
            **cluster_counts,
            "campaign_split_leakage": 0, "template_split_leakage": 0,
            "near_duplicate_split_leakage": 0, "normalized_text_split_leakage": 0,
            "labels": dict(labels), "pattern_outcomes": dict(outcomes), "splits": dict(splits)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
