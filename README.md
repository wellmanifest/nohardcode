# wellmanifest/nohardcode

Normative Wellmanifest domain pack for **identifying, classifying, and eliminating hardcoded data**, brittle heuristics, static coordinates, rigid keyword lists, and brittle algorithms by replacing them with proven dynamic and adaptive technologies (JEV, LLM, Tesseract OCR, YOLO, Secrets Vaults, env-dsl, adaptive latency governors, schema extractors, capability model routers, and DAG planners).

Status: `0.2.0-dev` — normative vocabulary, schemas, taxonomy, AST audit engine, and conformance test suite.

---

## 1. Purpose & Motivation

Hardcoding is one of the primary drivers of brittle systems, automation failures on minor UI changes, security vulnerabilities, and high maintenance costs:
- Hardcoded screen coordinates fail whenever screen resolution, scaling, or UI layouts shift.
- Hardcoded natural language keyword lists fail on minor typos, synonyms, or linguistic inflections.
- Plaintext API keys and secrets lead to critical credential leakage in version control.
- Hardcoded IP addresses and ports prevent containerization, dynamic port allocation, and multi-node mesh networking.
- Nested multi-branch `if/elif` decision logic obfuscates business rules and requires code redeployments for policy changes.
- Hardcoded timeouts and sleep calls trigger premature failures under load or waste throughput.
- Hardcoded model strings and provider APIs break upon vendor deprecations and prevent offline operation.
- Hardcoded display numbers (`:0`) and CUDA device targets fail in headless containers and CPU-only nodes.

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
| **Adaptive Performance & Latency Budgets** | `wellmanifest/performance` | RTT tracking, exponential jitter, dynamic timeouts and token governors |
| **Autonomous Self-Healing Loops** | `wellmanifest/repair-lifecycle` | Reactive plan-act-observe-diagnose-repair execution loops |
| **Multi-Agent Decision Governance** | `wellmanifest/agent` | Capability-based agent routing and bandit feedback prioritization |
| **Container & Process Virtualization** | `wellmanifest/dockuri` | URI-based container routing (`dockuri://...`) replacing hardcoded host/socket bindings |
| **Declarative App Packaging & Run** | `wellmanifest/apx` | Project packaging and execution replacing hardcoded tool invocation paths |
| **Project Single Source of Truth** | `wellmanifest/project-ssot` | Machine-readable project metadata replacing hardcoded repo details |
| **Canonical Documentation & Runbooks** | `wellmanifest/docs` | Standardized documentation architecture and codified markdown schemas |

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
| `NOHARDCODE-011` | Thresholds & Timeouts | Hardcoded sleeps `sleep(5)` & fixed retry counts | Adaptive Latency Backoff & Dynamic Rate Governors (`wellmanifest/performance`) |
| `NOHARDCODE-012` | Schema & DOM Extraction | Fragile single-path dict access & rigid regex | Resilient Multi-Stage Tree Visitors & LLM Healing (`wellmanifest/nl-dsl-llm`) |
| `NOHARDCODE-013` | Model & Engine Routing | Hardcoded model strings (`model="gpt-4o"`) | Capability-Based Model Router & Fallback Cascades (`wellmanifest/llm`) |
| `NOHARDCODE-014` | Procedural Workflows | Rigid step-by-step sequences & fixed loops | Goal-Driven DAG Planners & Self-Healing Loops (`wellmanifest/poa`) |
| `NOHARDCODE-015` | Environment & Hardware | Hardcoded `DISPLAY=":0"`, resolutions, `"cuda:0"` | Dynamic Hardware & Socket Capability Discovery (`wellmanifest/account-runtime`) |
| `NOHARDCODE-016` | Phonetics & Dictionaries | Static phonetic typo maps & literal equality | Fuzzy Phonetic Algorithms & Vector Embeddings (`wellmanifest/nl-dsl-llm`) |
| `NOHARDCODE-017` | Scoring & Prioritization | Fixed linear scoring equations & static weights | Online Preference Learning & Multi-Armed Bandits (`wellmanifest/saas-lifecycle`) |

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
