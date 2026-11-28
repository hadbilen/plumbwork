# ADR-0018: Property Ledger with Planted-Bug Red Proofs, Optional Playwright UI Matrix, Blind A/B Benchmark Evaluator, and `100x-engineer-skill` Release Tracking

**Date**: 2026-11-28
**Status**: accepted
**Deciders**: User, Model (Gemini 4 Neon, XHigh)
**Proposed By**: Model (Gemini 4 Neon, XHigh)
**Approved By**: User
**Authority**: Model Recommendation (User-Approved)

## Context

Comparative evaluation of `DeadInternetStudios/100x-engineer-skill` (`v0.1.1`, MIT) against Plumbwork (`v3.0.1`) identified three concrete verification gaps where Plumbwork relies on either manual conventions or static-only scanning:

1. **No code-hash-bound property ledger with planted-bug red proofs:** Plumbwork's `test-design` skill teaches red-then-green mutation thinking and `TestBoundaryGuard` prevents weakening existing tests (`GEMINI.md` Rule 9), but projects lack a git-tracked, file-hash-bound ledger (`verify/ledger.tsv`) that automatically marks behavioral properties `stale` on source edits and rejects properties that have never demonstrably failed on a planted defect (`verify/red/<id>.txt`).
2. **Static-only UI verification:** `ui-refinery` ships deterministic static HTML/CSS scanning (`check_ui_slop.py`) and WCAG AA color math (`contrast-check.py` / `contrast-mcp.py`), but lacks an optional multi-viewport live DOM/layout matrix (`blank`, `overflowX`, `offscreen`, `truncated`, `spill`, `tinyTap`, `tinyText`, `overlap`, `brokenImage`, `consoleErrors`, `viewportMeta`) for catching rendered mobile/responsive defects when Playwright is available.
3. **Manual A/B benchmark execution & implicit same-family auditing:** `docs/benchmark-protocol.md` defines a 10-task `OFF`/`ON` A/B protocol with an inline JSONL heredoc, but lacks an automated blinding/leak-scanning/HMAC-sealing pair builder, exact two-sided binomial sign-test and Wilson 95% confidence interval scoring, order-flip filtering, and mechanical same-model-family `self_review` detection.

At the same time, `ADR-0015` and `ADR-0017` froze `plumb-guard`'s top-level CLI surface at `25` public subcommands and `guard/__init__.py` exports at 16 symbols, while Plumbwork's core runtime must remain strictly Python standard-library-only (`3.10+`) and hermetic CI must not require a browser binary.

## Decision

1. **Property Ledger (`guard/property_ledger.py`):** Implement a zero-dependency, git-tracked property ledger (`verify/ledger.tsv` + `verify/red/<id>.txt`) enforcing 6 property kinds (`state`, `transition`, `precondition`, `postcondition`, `invariant`, `liveness`), canonical sorted SHA-256 `covers_hash` tracking, mandatory `^FAIL\s+\S` planted-bug red proof, waivers, and non-shell default execution (`shlex.split`, `shell=False`). Expose it through existing `plumb-guard test-boundary` actions (`ledger-add`, `ledger-run`, `ledger-sync`, `ledger-status`, `ledger-waive`) and `scripts/verify_invariants.py --property-ledger` (preserving the 25-subcommand `ADR-0015`/`ADR-0017` freeze and leaving `guard/__init__.py` unchanged).
2. **Optional Playwright Multi-Viewport UI Matrix (`skills/ui-refinery/scripts/check_ui_matrix.py`, `0o755`):** Implement a standalone-pack-safe pure DOM snapshot evaluator (`11` checks across `broken`/`weak`, testable via `--from-json`) paired with an optional Python `playwright.sync_api` driver. Enforce SSRF safety via `context.route("**/*", ...)` (covering popups), `context.route_web_socket("**/*", ...)` WebSocket blocking, `service_workers="block"`, and `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`: loopback-only by default, pinned-socket Python HTTP/HTTPS fulfillment with per-hop 3xx redirect validation under `--allow-remote`, a session-token and `Host`-verified ephemeral `127.0.0.1:0` server for local HTML (no directory listings, dotfiles, or symlinks), and exit `2` (`PLAYWRIGHT_MISSING`) without installing packages when Playwright is absent. Bundle the script in both `install.py`/`build_binaries.py` and the standalone `ui-refinery` plugin pack.
3. **Automated Blind A/B Benchmark Evaluator & Cross-Model Guidance (`scripts/benchmark_eval.py`):** Implement a standalone stdlib CLI (`init`, `pair`, `score`) preserving the existing `docs/benchmark-protocol.md` heredoc intact. Keep `seed` and `builder_model` sealed exclusively inside `0o600` `.private/key.json` (never in public `campaign.json`), derive slot polarity via keyed HMAC, bind per-order HMAC tokens to submission tree digests (`.private/key.seal`, outside `judge/`), normalize single-file names, run path+byte leak scanning with temp-dir staging, enforce mirrored `o1`/`o2` order-flip filtering, compute exact `math.comb` two-sided sign test + Wilson 95% CI, enforce strict numeric ledger validation, and fail closed under `--require-cross-model` on same-family or missing model provenance. Align `skills/harness/references/multi-agent-orchestration.md` cross-model guidance with Antigravity host constraints (Rules 15f & 17).
4. **Release-Only Upstream Tracking & MIT Attribution:** Add `DeadInternetStudios/100x-engineer-skill` to `skills/upstream-auditor/upstream_state.seed.json` and `guard/upstream.py` (`UpstreamAuditorBridge.load_state()`) as the 9th tracked repository using `"track": "release"` pinned at `v0.1.1` (avoiding high-churn `main` commit noise), and record full MIT attribution (`Copyright (c) 2026 Dead Internet Studios`) in `THIRD_PARTY_NOTICES.md`, `skills/ui-refinery/SKILL.md`, `guard/plugins.py`, and `README.md`.

## Alternatives Considered

### Alternative 1: Add 3 New Top-Level `plumb-guard` Subcommands (`property-ledger`, `ui-matrix`, `benchmark-eval`)
- **Pros**: Shorter invocation strings for each tool.
- **Cons**: Breaks the `ADR-0015`/`ADR-0017` 25-subcommand CLI surface freeze, widens `guard.py`/packaging/bash-completion surface, mixes repo-maintainer benchmark tooling (`scripts/benchmark_eval.py`) into external-project Guard commands, and forces avoidable contract test churn.
- **Why not**: Rejected under `GEMINI.md` Rule 4 (YAGNI) and `ADR-0015`/`ADR-0017` surface discipline; `test-boundary ledger-*`, `verify-invariants --property-ledger`, `skills/ui-refinery/scripts/check_ui_matrix.py`, and `scripts/benchmark_eval.py` fit existing seams cleanly.

### Alternative 2: Track `DeadInternetStudios/100x-engineer-skill` on `branch: "main"`
- **Pros**: Immediate visibility into every upstream commit.
- **Cons**: The repository is an active `v0.1.x` beta with frequent README, banner, and 19-language i18n commits, generating noisy 72-hour `SessionStart` drift alerts.
- **Why not**: Rejected; `"track": "release"` matches `morluto/rea` and `erkamyaman/rust-anything`, alerting only on published releases.

### Alternative 3: Bundle a Node.js Playwright Driver or JS Explicit-State Model Checker
- **Pros**: Supports Node-only Playwright installs and provides a built-in JS BFS model checker.
- **Cons**: Doubles untested browser IPC/SSRF surface in zero-browser CI and duplicates language-specific model checkers (`Kani`, `TLA+`, `Hypothesis`, `fast-check`) that `verify/ledger.tsv` already runs via generic commands.
- **Why not**: Rejected under YAGNI; Python `playwright.sync_api` provides a single auditable SSRF boundary in v1, and `PropertyLedger` remains language-agnostic.

## Consequences

### Positive
- Projects can opt into file-hash-tracked behavioral invariants with mechanical planted-bug red proof verification (`plumb-guard test-boundary ledger-status`, `plumb-guard verify-invariants --property-ledger`).
- `ui-refinery` gains live multi-viewport DOM/layout verification without sacrificing Plumbwork's zero-dependency Python stdlib core or hermetic CI.
- Harness A/B evaluations become mechanically blinded, leak-checked, tamper-sealed, statistically rigorous, and `self_review`-aware.
- Future `100x-engineer-skill` releases surface automatically in `/audit-upstream --skills` with zero commit-level noise and complete MIT attribution across both the full harness and standalone `ui-refinery` plugin pack.

### Negative
- Projects running live `check_ui_matrix.py` still require the user to install Python `playwright` and Chromium externally (explicitly declared under `GEMINI.md` Rule 8 when absent).
- Two existing contract tests asserting `len(tracked_repositories) == 8` (and the derived `8 - 1 == 7` subset assertion at `tests/test_adr0012_templates_ux_and_rustify.py:L501`) require authorized `8 -> 9` / `7 -> 8` updates (`tests/test_adr0012_templates_ux_and_rustify.py` lines 388 & 501, `tests/test_adr0014_predictive_handoff_rust_decisions_procoder.py` lines 1685 & 1700).

### Risks
- **Untrusted commands in `verify/ledger.tsv`:** Mitigated by never executing commands in `ledger-status` or `verify_invariants.py --property-ledger`, parsing `ledger-run` with `shlex.split` (`shell=False`), blocking shell operators and shell interpreters (`sh`, `bash`, `cmd`, `powershell`, `env`, `.bat`/`.cmd`) by default unless `--allow-shell` is passed, locking ledger mutations with `verify/.ledger.lock`, and isolating subprocess groups with bounded tail capture.
- **Browser SSRF during `check_ui_matrix.py`:** Mitigated by `context.route("**/*", ...)`, WebSocket blocking (`context.route_web_socket`), `service_workers="block"`, pinned-socket Python HTTP/HTTPS fulfillment with per-hop 3xx redirect validation under `--allow-remote`, and a session-token/`Host`-verified ephemeral `127.0.0.1:0` server for local HTML (direct user-supplied loopback URLs rely on `context.route` loopback host checks and do not rewrite dev-server redirects).
- **Local HMAC seal threat model in `benchmark_eval.py`:** Because `.private/audit.key` resides on the same machine, the HMAC seal stops accidental drift, post-pairing submission edits, and unsealed hand-typed verdicts but cannot defeat a local adversary who intentionally reads `.private/audit.key`; documented honestly per `GEMINI.md` Rule 8.
