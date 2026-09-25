from __future__ import annotations

import gzip
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


generator = load_module("dataset_generator", ROOT / "src" / "generate_dataset.py")
validator = load_module("dataset_validator", ROOT / "src" / "validate_dataset.py")


class DatasetTests(unittest.TestCase):
    def generate(self, count: int = 15000):
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name) / "data"
        manifest = generator.generate(path, count, 777)
        return temp, path, manifest

    def test_taxonomy_and_languages_are_unique(self):
        self.assertEqual(len(generator.taxonomy()), 60)
        self.assertEqual(len({x["id"] for x in generator.taxonomy()}), 60)
        self.assertEqual(len(generator.languages()), 50)
        self.assertEqual(len({x["code"] for x in generator.languages()}), 50)

    def test_schema_covers_every_generated_field(self):
        row = generator.base_record(0, "scam", generator.taxonomy()[0], generator.languages()[0])
        record_schema = generator.schema()
        self.assertEqual(set(record_schema["required"]), set(row))
        self.assertEqual(set(record_schema["properties"]), set(row))
        self.assertIs(record_schema["additionalProperties"], False)

    def test_data_dictionary_matches_schema(self):
        # Regression: the dictionary once documented ten fields that do not
        # exist (id, locale_hint, urgency, ...) and omitted eight that do.
        text = (ROOT / "docs" / "DATA_DICTIONARY.md").read_text(encoding="utf-8")
        documented = set(re.findall(r"^\| [A-Za-z]+ \| `([a-z_]+)` \|", text, re.M))
        self.assertEqual(documented, set(generator.schema()["properties"]))

    def test_small_builds_report_missing_heldout_splits(self):
        self.assertEqual(generator.empty_splits({"split_counts": {"train": 100}}), ["development", "test"])
        full = {"split_counts": {"train": 8, "development": 1, "test": 1}}
        self.assertEqual(generator.empty_splits(full), [])

    def test_manifest_paths_are_portable(self):
        # Regression: str(Path) wrote backslashes on Windows and the validator
        # (correctly) rejected them, so nothing validated there.
        temp, path, manifest = self.generate(600)
        try:
            for entry in manifest["files"]:
                self.assertNotIn("\\", entry["path"])
            self.assertEqual(validator.validate(path)["status"], "passed")
        finally:
            temp.cleanup()

    def test_generation_is_deterministic(self):
        a, pa, ma = self.generate(1000)
        b, pb, mb = self.generate(1000)
        try:
            self.assertEqual(ma["label_counts"], mb["label_counts"])
            with gzip.open(pa / "shards" / "part-00000.jsonl.gz", "rt", encoding="utf-8") as left:
                left_rows = left.read()
            with gzip.open(pb / "shards" / "part-00000.jsonl.gz", "rt", encoding="utf-8") as right:
                right_rows = right.read()
            self.assertEqual(left_rows, right_rows)
        finally:
            a.cleanup(); b.cleanup()

    def test_small_release_validates(self):
        temp, path, manifest = self.generate()
        try:
            result = validator.validate(path)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["records"], manifest["records"])
            self.assertEqual(result["languages"], 50)
            self.assertEqual(result["families"], 60)
        finally:
            temp.cleanup()

    def test_no_live_urls_and_campaign_split_is_stable(self):
        temp, path, _ = self.generate(3000)
        try:
            for shard in sorted((path / "shards").glob("*.gz")):
                with gzip.open(shard, "rt", encoding="utf-8") as handle:
                    for line in handle:
                        row = json.loads(line)
                        self.assertNotIn("http://", row["text"].lower())
                        self.assertNotIn("https://", row["text"].lower())
                        self.assertEqual(row["split"], validator.expected_split(row["template_cluster_id"]))
        finally:
            temp.cleanup()

    def test_adversarial_modes_preserve_reserved_defanged_host(self):
        text = "Verify account at hxxps://example-7[.]invalid/verify/0007 now"
        for mode in generator.EVASIONS:
            changed = generator.adversarial(text, mode)
            hosts = validator.DEFANGED_HOST.findall(changed)
            self.assertEqual(hosts, ["example-7[.]invalid"])

    def test_benign_and_hard_negative_are_not_named_as_scam(self):
        family = generator.taxonomy()[0]
        lang = generator.languages()[0]
        benign = generator.base_record(1, "benign", family, lang)
        hard = generator.base_record(2, "hard_negative", family, lang)
        self.assertIsNone(benign["scam_family"])
        self.assertEqual(benign["pattern_outcome"], "none")
        self.assertEqual(hard["pattern_outcome"], "none")
        self.assertIsNone(hard["scam_family"])
        self.assertEqual(hard["scenario_family"], family["id"])
        self.assertIsNone(hard["requested_action"])

    def test_conversation_requires_action_anchor_before_identification(self):
        family = generator.taxonomy()[0]
        lang = generator.languages()[0]
        observed = {}
        for index in range(100):
            row = generator.base_record(index, "conversation_turn", family, lang)
            observed.setdefault(row["conversation_stage"], row)
        self.assertEqual(set(observed), {"contact", "trust_building", "pretext", "pressure", "action_request"})
        for stage, row in observed.items():
            if stage == "action_request":
                self.assertEqual(row["pattern_outcome"], "identified")
                self.assertEqual(row["scam_family"], family["id"])
                self.assertIsNotNone(row["requested_action"])
            else:
                self.assertEqual(row["pattern_outcome"], "undetermined")
                self.assertIsNone(row["scam_family"])
                self.assertIsNone(row["requested_action"])

    def test_related_clusters_share_one_split(self):
        rows = []
        family = generator.taxonomy()[0]
        lang = generator.languages()[0]
        for index in (0, 60_000, 120_000):
            rows.append(generator.base_record(index, "scam", family, lang))
        by_campaign = {}
        by_near_duplicate = {}
        for row in rows:
            by_campaign.setdefault(row["campaign_id"], set()).add(row["split"])
            by_near_duplicate.setdefault(row["near_duplicate_cluster_id"], set()).add(row["split"])
        self.assertTrue(all(len(values) == 1 for values in by_campaign.values()))
        self.assertTrue(all(len(values) == 1 for values in by_near_duplicate.values()))

    def test_generated_release_contains_anchor_provenance(self):
        temp, path, manifest = self.generate(100)
        try:
            payload = json.loads((path / "curated_anchor_packs.json").read_text(encoding="utf-8"))
            self.assertEqual(len(payload["languages"]), 18)
            self.assertEqual(payload["review_status"], "not_native_reviewed")
            self.assertIn("curated_anchor_packs.json", {item["path"] for item in manifest["files"]})
        finally:
            temp.cleanup()

    def test_anchor_pack_is_mandatory_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaises(FileNotFoundError):
                generator.load_anchor_payload(missing)
            invalid = Path(directory) / "invalid.json"
            invalid.write_text('{"languages": {}, "licence": "wrong"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                generator.load_anchor_payload(invalid)

    def test_language_quality_tiers_are_explicit(self):
        family = generator.taxonomy()[0]
        curated = next(item for item in generator.languages() if item["code"] == "zh")
        seed_only = next(item for item in generator.languages() if item["code"] == "sw")
        curated_row = generator.base_record(0, "scam", family, curated)
        seed_row = generator.base_record(1, "scam", family, seed_only)
        self.assertEqual(curated_row["language_quality_tier"], "A")
        self.assertIn("curated_anchor_pack", curated_row["quality_flags"])
        self.assertEqual(seed_row["language_quality_tier"], "B")
        self.assertIn("generic_seed_only", seed_row["quality_flags"])
        self.assertEqual(curated_row["native_review_status"], "not_reviewed")

    def test_every_quality_tier_matches_anchor_availability(self):
        rows = generator.languages()
        self.assertEqual(sum(row["coverage_tier"] == "A" for row in rows), 18)
        for row in rows:
            expected = "A" if row["code"] in generator.CURATED_ANCHORS else "B"
            self.assertEqual(row["coverage_tier"], expected)

    def test_public_generator_rejects_invalid_arguments(self):
        family = generator.taxonomy()[0]
        lang = generator.languages()[0]
        with self.assertRaises(ValueError):
            generator.base_record(0, "unknown", family, lang)
        with self.assertRaises(ValueError):
            generator.base_record(-1, "scam", family, lang)
        with self.assertRaises(ValueError):
            generator.split_for_variant(20)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                generator.generate(Path(directory) / "data", 0, 100)

    def test_label_allocation_is_exact_and_non_negative(self):
        for records in range(1, 101):
            schedule = generator.label_schedule(records)
            self.assertEqual(sum(count for _, count in schedule), records)
            self.assertTrue(all(count >= 0 for _, count in schedule))
        self.assertEqual(dict(generator.label_schedule(1_500_000)), generator.DEFAULT_COUNTS)

    def test_regeneration_removes_obsolete_shards(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            generator.generate(path, 2000, 500)
            self.assertEqual(len(list((path / "shards").glob("*.jsonl.gz"))), 4)
            generator.generate(path, 1000, 500)
            self.assertEqual(len(list((path / "shards").glob("*.jsonl.gz"))), 2)
            self.assertEqual(validator.validate(path)["records"], 1000)

    def test_generator_refuses_unmanaged_nonempty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unrelated"
            path.mkdir()
            protected = path / "keep.txt"
            protected.write_text("do not replace", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unmanaged output"):
                generator.generate(path, 100, 25)
            self.assertEqual(protected.read_text(encoding="utf-8"), "do not replace")

    def test_generator_refuses_symbolic_link_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "output-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                # Windows requires an elevated privilege or Developer Mode.
                self.skipTest(f"symbolic links are not permitted here: {exc}")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                generator.generate(link, 100, 25)
            self.assertEqual(list(target.iterdir()), [])

    def test_generator_refuses_filesystem_root(self):
        with self.assertRaisesRegex(ValueError, "filesystem root"):
            generator.validate_output_target(Path(Path.cwd().anchor))

    def test_generation_failure_removes_temporary_files(self):
        original = generator.base_record

        def fail_after_five(index, kind, family, lang):
            if index == 5:
                raise RuntimeError("controlled test failure")
            return original(index, kind, family, lang)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            generator.generate(path, 100, 25)
            original_manifest = (path / "manifest.json").read_bytes()
            with mock.patch.object(generator, "base_record", side_effect=fail_after_five):
                with self.assertRaisesRegex(RuntimeError, "controlled test failure"):
                    generator.generate(path, 200, 10)
            self.assertEqual((path / "manifest.json").read_bytes(), original_manifest)
            self.assertEqual(validator.validate(path)["records"], 100)
            self.assertEqual(list(Path(directory).rglob("*.tmp")), [])
            self.assertEqual(list(Path(directory).glob(".data.generate-*")), [])
            self.assertEqual(list(Path(directory).glob(".data.backup-*")), [])

    def test_validator_rejects_unlisted_shards(self):
        temp, path, _ = self.generate(3000)
        try:
            with gzip.open(path / "shards" / "part-99999.jsonl.gz", "wt", encoding="utf-8"):
                pass
            with self.assertRaisesRegex(ValueError, "shard inventory"):
                validator.validate(path)
        finally:
            temp.cleanup()

    def test_validator_rejects_manifest_path_traversal(self):
        temp, path, _ = self.generate(3000)
        try:
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["path"] = "../outside.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe manifest path"):
                validator.validate(path)
        finally:
            temp.cleanup()

    def test_validator_requires_all_metadata_in_manifest(self):
        temp, path, _ = self.generate(3000)
        try:
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != "schema.json"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "omits required metadata"):
                validator.validate(path)
        finally:
            temp.cleanup()

    def test_validator_recomputes_normalized_cluster(self):
        row = generator.base_record(0, "scam", generator.taxonomy()[0], generator.languages()[0])
        self.assertEqual(row["normalized_text_cluster_id"], validator.expected_normalized_cluster(row["text"]))
        changed = dict(row)
        changed["normalized_text_cluster_id"] = "TXT-0000000000000000"
        self.assertNotEqual(changed["normalized_text_cluster_id"], validator.expected_normalized_cluster(changed["text"]))

    def test_validator_reconciles_quality_report(self):
        temp, path, _ = self.generate(3000)
        try:
            quality_path = path / "quality_report.json"
            quality = json.loads(quality_path.read_text(encoding="utf-8"))
            quality["records"] = 1
            quality_path.write_text(json.dumps(quality), encoding="utf-8")
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(item for item in manifest["files"] if item["path"] == "quality_report.json")
            entry["bytes"] = quality_path.stat().st_size
            entry["sha256"] = validator.sha256(quality_path)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "quality report mismatch"):
                validator.validate(path)
        finally:
            temp.cleanup()

    def test_validator_reconciles_preview(self):
        temp, path, _ = self.generate(3000)
        try:
            preview_path = path / "preview.jsonl"
            rows = preview_path.read_text(encoding="utf-8").splitlines()
            first = json.loads(rows[0])
            first["text"] = "altered preview"
            rows[0] = json.dumps(first, ensure_ascii=False)
            preview_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(item for item in manifest["files"] if item["path"] == "preview.jsonl")
            entry["bytes"] = preview_path.stat().st_size
            entry["sha256"] = validator.sha256(preview_path)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "preview does not match"):
                validator.validate(path)
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
