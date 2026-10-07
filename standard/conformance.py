#!/usr/bin/env python3
"""
Dependency-free conformance checker for wellmanifest/nohardcode v0.1.0-dev.
Validates schemas, manifests, documentation, valid/invalid fixtures, and AST scanner.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from nohardcode_check import (
    ConformanceError,
    scan_file_content,
    validate_detection_rule_document,
    validate_policy_document,
)

ROOT = Path(__file__).resolve().parent
PACK = ROOT.parent

REQUIRED_DOCS = (
    PACK / "README.md",
    PACK / "AGENTS.md",
    PACK / "GEMINI.md",
    PACK / "VERSION",
    PACK / "dsl-manifest.json",
    PACK / "docs/SPEC.md",
    PACK / "docs/ARCHITECTURE.md",
    PACK / "docs/ADOPTION_GUIDE.md",
    PACK / "docs/TAXONOMY_AND_USE_CASES.md",
    PACK / "schemas/nohardcode-policy.schema.json",
    PACK / "schemas/detection-rule.schema.json",
)

VALID_FIXTURES = (
    ROOT / "fixtures/valid/policy.json",
    ROOT / "fixtures/valid/detection-rule.json",
)

INVALID_FIXTURES = {
    ROOT / "fixtures/invalid/policy-invalid-schema.json": "NOHARDCODE_POLICY_INVALID",
    ROOT / "fixtures/invalid/policy-invalid-profile.json": "NOHARDCODE_PROFILE_INVALID",
    ROOT / "fixtures/invalid/detection-rule-invalid-id.json": "DETECTION_RULE_ID_INVALID",
    ROOT / "fixtures/invalid/detection-rule-invalid-category.json": "DETECTION_RULE_CATEGORY_INVALID",
}


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ConformanceError("PARSE_ERROR", f"Invalid JSON in {path.name}: {error}") from error
    if not isinstance(data, dict):
        raise ConformanceError("PARSE_ERROR", f"Expected JSON object in {path.name}")
    return data


def validate_fixture(path: Path) -> None:
    data = load_json(path)
    if "rule_id" in data:
        validate_detection_rule_document(data)
    else:
        validate_policy_document(data)


def test_code_smell_scanner() -> None:
    # Test synthetic snippet with violations
    smelly_code = """
import pyautogui

KEYWORDS = ["uruchom", "włącz", "graj", "otwórz", "startuj", "odtwarzaj"]

def bad_worker():
    api_key = "abcdef1234567890abcdef1234567890"
    pyautogui.click(500, 200)
    print("starting worker on localhost:7070")
    home_dir = "/home/tom/data"
"""
    violations = scan_file_content(Path("worker_service.py"), smelly_code, profile="strict")
    rule_ids = {v.rule_id for v in violations}

    expected_rules = {"NOHARDCODE-001", "NOHARDCODE-002", "NOHARDCODE-005", "NOHARDCODE-006", "NOHARDCODE-007", "NOHARDCODE-009"}
    missing = expected_rules - rule_ids
    if missing:
        raise ConformanceError("SCANNER_FAILURE", f"AST scanner missed expected rules: {missing}")


def run_conformance() -> int:
    print("=== Wellmanifest No-Hardcode Conformance Suite ===")

    # 1. Required Documents
    for req in REQUIRED_DOCS:
        if not req.exists():
            print(f"✗ Missing required document: {req.relative_to(PACK)}", file=sys.stderr)
            return 1
    print(f"✓ All {len(REQUIRED_DOCS)} required documents and schemas present.")

    # 2. Version Consistency
    version_text = (PACK / "VERSION").read_text(encoding="utf-8").strip()
    manifest_data = load_json(PACK / "dsl-manifest.json")
    if manifest_data.get("version") != version_text:
        print(f"✗ Version mismatch: VERSION is '{version_text}', manifest is '{manifest_data.get('version')}'", file=sys.stderr)
        return 1
    print(f"✓ Version consistency verified: {version_text}")

    # 3. Valid Fixtures
    for vf in VALID_FIXTURES:
        if not vf.exists():
            print(f"✗ Missing valid fixture: {vf.name}", file=sys.stderr)
            return 1
        try:
            validate_fixture(vf)
            print(f"✓ Valid fixture passed: {vf.name}")
        except Exception as ex:
            print(f"✗ Valid fixture failed unexpectedly: {vf.name} -> {ex}", file=sys.stderr)
            return 1

    # 4. Invalid Fixtures
    for inv, expected_code in INVALID_FIXTURES.items():
        if not inv.exists():
            print(f"✗ Missing invalid fixture: {inv.name}", file=sys.stderr)
            return 1
        try:
            validate_fixture(inv)
            print(f"✗ Invalid fixture was unexpectedly accepted: {inv.name}", file=sys.stderr)
            return 1
        except ConformanceError as ce:
            if ce.code != expected_code:
                print(f"✗ Invalid fixture raised wrong code: expected {expected_code}, got {ce.code}", file=sys.stderr)
                return 1
            print(f"✓ Invalid fixture rejected as expected ({ce.code}): {inv.name}")
        except Exception as ex:
            print(f"✗ Unexpected exception on invalid fixture {inv.name}: {ex}", file=sys.stderr)
            return 1

    # 5. Scanner Unit Test
    try:
        test_code_smell_scanner()
        print("✓ Smell detection AST scanner verified against normative rules.")
    except Exception as ex:
        print(f"✗ Smell detection scanner test failed: {ex}", file=sys.stderr)
        return 1

    print("\nAll conformance tests PASSED. Status: COMPLIANT.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Wellmanifest No-Hardcode Conformance Runner")
    parser.add_argument("--all", action="store_true", help="Run full suite")
    args = parser.parse_args()
    return run_conformance()


if __name__ == "__main__":
    sys.exit(main())
