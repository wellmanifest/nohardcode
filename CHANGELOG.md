# Changelog

All notable changes to `wellmanifest/nohardcode` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0-dev] - 2026-10-07

### Added
- Initial specification of `wellmanifest/nohardcode` (normative unhardcoding standard).
- 10 core anti-pattern categories and their dynamic counterparts (LLM, JEV, Tesseract OCR, YOLO Vision, etc.).
- Integration and adoption matrix with existing `wellmanifest/*` standards (`secrets`, `env-dsl`, `logs`, `anonym`, `reuse`, `poa`).
- JSON Schema for repository-level nohardcode policy (`schemas/nohardcode-policy.schema.json`).
- JSON Schema for detection and remediation rules (`schemas/detection-rule.schema.json`).
- Conformance and codebase audit engine (`standard/nohardcode_check.py`).
- Detailed taxonomy and multi-domain use cases (`docs/TAXONOMY_AND_USE_CASES.md`).
- Step-by-step adoption guide (`docs/ADOPTION_GUIDE.md`).
- Normative requirements specification (`docs/SPEC.md`).
- Architecture and boundary document (`docs/ARCHITECTURE.md`).
