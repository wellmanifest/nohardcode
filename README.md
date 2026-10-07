# wellmanifest/nohardcode

Normative Wellmanifest domain pack for **identifying, classifying, and eliminating hardcoded data**, brittle heuristics, static coordinates, rigid keyword lists, and unmanaged constants by replacing them with proven dynamic technologies (JEV, LLM, Tesseract OCR, YOLO, Secrets Vaults, and env-dsl).

Status: `0.1.0-dev` — normative vocabulary, schemas, taxonomy, AST audit engine, and conformance test suite.

---

## 1. Purpose & Motivation

Hardcoding is one of the primary drivers of brittle systems, automation failures on minor UI changes, security vulnerabilities, and high maintenance costs:
- Hardcoded screen coordinates fail whenever screen resolution, scaling, or UI layouts shift.
- Hardcoded natural language keyword lists fail on minor typos, synonyms, or linguistic inflections.
- Plaintext API keys and secrets lead to critical credential leakage in version control.
- Hardcoded IP addresses and ports prevent containerization, dynamic port allocation, and multi-node mesh networking.
- Nested multi-branch `if/elif` decision logic obfuscates business rules and requires code redeployments for policy changes.

`wellmanifest/nohardcode` defines the standard for **dynamic, resilient, and adaptive software construction**.

---

## 2. HOME vs ADOPT (Boundary Matrix)

- `HOME` wellmanifest · `shape` domain_pack
- Cross-refs (ADOPT, do not duplicate):

| Concern | HOME | Role in Unhardcoding |
|:---|:---|:---|
| **Unhardcode Taxonomy & AST Audit Engine** | **this pack** | Normative classification, AST scanner, and dynamic technology mapping rules |
| **Dynamic Secrets & Credentials** | `wellmanifest/secrets` | AES-256-GCM encrypted envelopes, origin-bound access, short-lived bounded leases |
| **Dynamic Configuration & Environment** | `wellmanifest/env-dsl` | Language-neutral `SNAKE_CASE=value` constants, typed `.env` contract |
| **Structured Errors & Codified Runbooks** | `wellmanifest/logs` | CQRS JSONL streams, exact URI processes, error runbooks (`errors/{CODE}.md`) |
| **AST Deduplication & Reuse Engine** | `wellmanifest/reuse` | `semcod/redup` AST clone detection, `semcod/search` FTS5 index |
| **PII Anonymization & Synthetic Data** | `wellmanifest/anonym` | Data masking, pseudonymization, GDPR compliance |
| **Runtime Isolation & Path Portability** | `wellmanifest/account-runtime` | Bounded user workspace, sandboxed profiles, dynamic home directories |
| **Declarative Process URIs** | `wellmanifest/poa` | `proc://...` execution contracts replacing raw shell scripts |
| **Natural Language & Intent Models** | `wellmanifest/nl-dsl-llm` | Formal grammar and LLM intent translation contracts |

---

## 3. Normative Rules Summary

| Rule ID | Category | Forbidden Hardcoded Anti-Pattern | Required Dynamic Replacement |
|:---|:---|:---|:---|
| `NOHARDCODE-001` | Intent & Natural Language | Static arrays of >5 keyword literals for NL routing | Semantic Router / Local LLM (`wellmanifest/nl-dsl-llm`) |
| `NOHARDCODE-002` | UI Automation | Fixed pixel coordinates `(x, y)` | YOLOv8/v11 UI object detection (`twinerd-vision`) or accessibility trees |
| `NOHARDCODE-003` | Visual Text Localization | Hardcoded click offsets on canvas/VNC | Tesseract OCR bounding box resolution (`pytesseract`) |
| `NOHARDCODE-004` | Business Decision Logic | Multi-branch (>3) hardcoded `if/elif` ladders | Declarative JEV policy expressions (`wellmanifest/policy-dsl`) |
| `NOHARDCODE-005` | Secrets & Tokens | Plaintext API keys, passwords, bearer tokens | Authenticated symmetric envelopes (`wellmanifest/secrets`) |
| `NOHARDCODE-006` | Network & Endpoints | Hardcoded localhost IPs and TCP/UDP ports | Typed environment variables (`wellmanifest/env-dsl`) |
| `NOHARDCODE-007` | Operational Logging | Raw `print()` or `console.log()` calls | Structured JSONL logging & codified runbooks (`wellmanifest/logs`) |
| `NOHARDCODE-008` | Test Data & Fixtures | Real personal data (PII) in mocks | Deterministic masking and pseudonymization (`wellmanifest/anonym`) |
| `NOHARDCODE-009` | Filesystem Paths | Hardcoded user paths (e.g. `/home/username`) | Standard APIs (`Path.home()`, `XDG_*`, `wellmanifest/account-runtime`) |
| `NOHARDCODE-010` | Code Duplication | Copy-pasted helper functions across repos | Shared packages under `packages/` (`wellmanifest/reuse`) |

---

## 4. Artifacts

- **Taxonomy & Use Cases**: [`docs/TAXONOMY_AND_USE_CASES.md`](docs/TAXONOMY_AND_USE_CASES.md)
- **Specification**: [`docs/SPEC.md`](docs/SPEC.md)
- **Architecture & Ecosystem**: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Adoption Guide**: [`docs/ADOPTION_GUIDE.md`](docs/ADOPTION_GUIDE.md)
- **Schemas**:
  - [`schemas/nohardcode-policy.schema.json`](schemas/nohardcode-policy.schema.json)
  - [`schemas/detection-rule.schema.json`](schemas/detection-rule.schema.json)
- **Audit & Conformance CLI**: [`standard/nohardcode_check.py`](standard/nohardcode_check.py)
- **Conformance Suite**: [`standard/conformance.py`](standard/conformance.py)

---

## 5. Usage & Conformance Verification

To run the full conformance test suite:
```bash
python3 standard/conformance.py --all
```

To audit a target repository for hardcoded smells:
```bash
python3 standard/nohardcode_check.py --target /path/to/repo --profile balanced
```
