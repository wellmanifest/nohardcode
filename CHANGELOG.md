# Changelog

All notable changes to `wellmanifest/nohardcode` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0-dev] - 2026-10-08

### Added
- Expanded normative rules from 10 to 17 rules:
  - `NOHARDCODE-011`: Adaptive Thresholds, Dynamic Timeouts & Rate Governors (EWMA RTT latency, full jitter backoff).
  - `NOHARDCODE-012`: Resilient Schema Extraction & Document/DOM Decoding (schema-tolerant AST tree visitors, zero-shot LLM fallback).
  - `NOHARDCODE-013`: Dynamic Model, Provider & Engine Capabilities Routing (abstract requirements routing, local/cloud fallback cascades).
  - `NOHARDCODE-014`: Declarative Goal-Driven DAG Planning & Reactive Workflows (goal DAGs, self-repair loops).
  - `NOHARDCODE-015`: Environment & Hardware Capability Discovery (display socket probing, hardware acceleration probes).
  - `NOHARDCODE-016`: Fuzzy Phonetic Matching & Lexical Resilience (Double Metaphone, Levenshtein distance, embedding similarity).
  - `NOHARDCODE-017`: Feedback-Driven Prioritization & Dynamic Scoring (Multi-Armed Bandits, Thompson Sampling, outcome learning).
- Added 7 new engine bindings to `schemas/nohardcode-policy.schema.json` (`adaptive_budget`, `schema_extractor`, `model_router`, `dag_planner`, `hardware_probe`, `fuzzy_phonetic`, `adaptive_ranking`).
- Extended AST smell scanner `standard/nohardcode_check.py` to detect static sleep delays (`NOHARDCODE-011`), hardcoded AI model strings (`NOHARDCODE-013`), and hardcoded display/device targets (`NOHARDCODE-015`).
- Updated taxonomy catalog and practical implementation guides (`docs/TAXONOMY_AND_USE_CASES.md`).
- Published remote GitHub repository at `https://github.com/wellmanifest/nohardcode`.

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
