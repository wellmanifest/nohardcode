# Wellmanifest No-Hardcode Standard Specification
## `wellmanifest/nohardcode@v1`

## 1. Scope & Status

This specification defines normative rules for identifying, preventing, and eliminating hardcoded values, brittle static heuristics, and rigid assumptions across all repositories complying with the `wellmanifest` standard.

Status: `0.1.0-dev`.

---

## 2. Normative Rules

### `NOHARDCODE-001`: Natural Language & Intent Decoupling
1. Codebases MUST NOT maintain static arrays of more than 5 natural language keyword literals for intent classification where semantic classification is required.
2. User intent mapping MUST use a semantic router, embedding model, or local LLM prompt (`wellmanifest/nl-dsl-llm`) with tolerance for grammatical inflection, typos, and phrasing variations.
3. Keyword lists in legacy bridges MUST provide a deterministic fallback or escalation to an LLM evaluator before raising an unknown-command error.

### `NOHARDCODE-002`: UI Spatial Coordinate Decoupling
1. Automation scripts MUST NOT emit fixed, hardcoded absolute mouse click coordinates `(x, y)` without explicit dynamic bounding box calculation.
2. Element positioning MUST be derived dynamically using visual object detection (YOLO / `twinerd-vision`), accessibility trees, or OCR text bounding boxes.

### `NOHARDCODE-003`: Visual Label & Text Dynamic Extraction
1. Canvas, VNC, and KVM screen interactions MUST use OCR (Tesseract OCR / EasyOCR) to dynamically localize target text elements when DOM selectors are unavailable.
2. OCR confidence thresholds MUST be configurable per environment (defaulting to `>= 60.0`).

### `NOHARDCODE-004`: Declarative Business Logic (JEV / Policy DSL)
1. Multi-branch decision logic containing more than 3 consecutive conditional branches based on data values SHOULD be externalized into declarative JSON/YAML expressions (JEV / JSONLogic / `wellmanifest/policy-dsl`).
2. Hardcoded thresholds and coefficients MUST be loadable from external policy manifests.

### `NOHARDCODE-005`: Plaintext Credential Prohibition
1. Source files, documentation, and configuration templates MUST NOT contain plaintext API keys, tokens, passwords, or cryptographic private keys.
2. All persistent secrets MUST comply with `wellmanifest/secrets` (AES-256-GCM authenticated envelopes, `0600` permissions, origin-bound access).

### `NOHARDCODE-006`: Environment & Port Externalization
1. Hostnames, IP addresses, and TCP/UDP ports MUST NOT be hardcoded as string/int literals in application logic.
2. Configuration MUST resolve through standard environment variables conforming to `wellmanifest/env-dsl` (`SNAKE_CASE=value`).

### `NOHARDCODE-007`: Structured Logging & Codified Errors
1. Applications MUST NOT emit unstructured raw string prints (`print()`, `console.log()`) for operational events or fatal conditions.
2. All errors and exceptions MUST adopt structured error codes documented in `errors/{CODE}.md` runbooks according to `wellmanifest/logs`.

### `NOHARDCODE-008`: PII & Test Fixture Hygiene
1. Test fixtures, sample datasets, and mock objects MUST NOT contain real personal data (PII) of real individuals or production systems.
2. Data masking, synthetic generation, or pseudonymization conforming to `wellmanifest/anonym` MUST be applied.

### `NOHARDCODE-009`: Filesystem Path Portability
1. Code MUST NOT assume user home directory names (e.g. `/home/tom`, `C:\Users\tom`).
2. Paths MUST be resolved dynamically via standard platform APIs (`Path.home()`, `XDG_*`, or `tempfile`) and bounded runtime leases (`wellmanifest/account-runtime`).

### `NOHARDCODE-010`: Code Duplication & Shared Module Reuse
1. Codebases MUST NOT copy-paste identical logic across multiple repositories or subdirectories.
2. Duplication detected by AST analysis (`semcod/redup`) MUST be extracted into modular packages under `packages/` or dedicated micro-libraries conforming to `wellmanifest/reuse` and `wellmanifest/modularity`.

---

## 3. Conformance Profiles

- **Strict**: All rules (`NOHARDCODE-001` through `NOHARDCODE-010`) are evaluated as blocking errors (`exit code 1`).
- **Balanced (Default)**: `NOHARDCODE-005`, `NOHARDCODE-006`, `NOHARDCODE-007`, `NOHARDCODE-009` are blocking errors. `NOHARDCODE-001` through `NOHARDCODE-004` and `NOHARDCODE-010` are reported as warnings with recommended refactoring tickets.
- **Permissive**: All findings are advisory warnings with automated planfile ticket suggestions.
