# Changelog

All notable changes to `wellmanifest/nohardcode` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Reviewed inline waivers `# nohardcode: allow NOHARDCODE-NNN -- reason`:
  kept in the report as `waived` with the reason, never blocking (#5).
- Waivers for formats without trailing comments: the pragma on the comment-only
  line directly above a finding (Dockerfile), and exact policy `waivers`
  (`path`, `rule`, `reason`, optional `match`) for JSON. The active policy file
  is no longer scanned (#9).

### Fixed
- Line rules also run on C/C++, `.oql`, `.toml`, `.tsx/.jsx`, `.conf`, `.ini`,
  `.env*`, `Dockerfile*` and unit files; `#define` in C is no longer skipped as a
  comment; NOHARDCODE-006 detects private (RFC 1918) host addresses; the report
  has `summary.coverage` (#7).
- NOHARDCODE-007 exempts CLI/test files by repository-relative path component
  and filename word instead of any substring of the full path (`latest.py`,
  `checkout.py`, `client.py` and host directories no longer suppress it); an
  explicit `"exclusions": []` scans everything instead of the defaults (#11).
- NOHARDCODE-006 skips env-lookup defaults in JS/TS (`process.env.X || "..."`,
  `import.meta.env.X ?? "..."`, `config().X || "..."`) and shell
  (`${X:-...}`) like it already did for Python; NOHARDCODE-011 exempts tests and
  fixtures by path component and filename word instead of substring (#13).
- Loopback endpoints on `KEY=value` lines of `.env*` files are configuration and
  no longer reported; private (RFC 1918) hosts there still are (#15).
- `NOHARDCODE-006` no longer reports the default value of an environment
  lookup (`os.getenv`, `os.environ.get`, `os.environ.setdefault`) — the
  env-dsl remediation the adoption guide prescribes (#1).
- The checker applies a repository policy's per-rule `enabled` and
  `severity`; before, only `profile` and `exclusions` were used (#3).

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
