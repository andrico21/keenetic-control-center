# Reviewer brief: kcc full code review (read-only)

Repository: `/home/andrico/keenetic-control-center`, branch `master`, HEAD `349b7fb`.
kcc is a Rust 1.100 workspace: a control center for Keenetic/Netcraze routers over their
RCI HTTP API, with a Web UI (axum + askama + htmx, the main surface), an MCP server
(rmcp-server-kit 3.21 / rmcp 3.9) and a CLI. All of it was written by an AI worker; you
review it from scratch.

## Rules for you

- READ-ONLY. Never edit, create or delete files in the repository. Do not run `cargo`
  (builds/tests share a target dir with other reviewers). Use read/grep/rg/sed/git log/
  git show only. Do not contact any network host.
- Read the code itself. Do not rely on comments, docs, commit messages or the plan files
  under `.omo/` to tell you what the code does.
- Every finding cites `path:line` ranges you opened in THIS session and quotes the
  minimal code (at most 12 lines). Anything you did not verify is marked INFERRED.
- A finding needs a concrete consequence: for a bug or security issue, the input or
  sequence and the wrong outcome; for a guideline issue, the rule and why the code
  breaks it. No speculation-only findings, no pure style nits.

## The standard

1. `docs/rust-guidelines/RUST_GUIDELINES.md` (identical to upstream
   andrico21/rust-guidelines at 49898c9, the current HEAD). Read sections 1-8, section 9
   "Satisfying the profile" (around lines 2038-2140) so you know which idioms the lint
   profile FORCES (do not flag those), section 10 (security and supply chain), section 11
   (quick reference checklist), section 13 (testing quality).
2. `docs/rust-guidelines/overlays/domains/http-services.md` and `mcp-servers.md`.
3. `docs/rust-guidelines/overlays/projects/keenetic-control-center.md` (project rules
   (a)-(i): outbound policy, raw input validated against the catalog, curated writes read
   back, secrets in secrecy/zeroize types never in logs/audit/tool results/errors/Debug,
   Web UI hardening, i18n, live tests only on test devices, privacy) and `AGENTS.md`.

## What to look for

1. Correctness bugs (wrong results, broken error paths, races, cancellation hazards,
   panics reachable from input, integer/size handling, unbounded growth).
2. Security across the trust boundaries: Web user with a role, MCP client (an AI agent
   that may be prompt-injected), API keys, the LAN (router responses are untrusted input),
   local users on the host. Authn/authz and router scope, CSRF, XSS/template escaping, CSP,
   SSRF/outbound policy, injection into router CLI lines or RCI paths, path traversal in
   state/backup/preset files, secret leakage (logs, audit, errors, Debug, HTML, MCP
   results, files at rest, file modes), crypto misuse, timing, DoS bounds.
3. Rust guideline violations that the lint profile cannot catch (the semantic DO/DON'T
   rules: ownership, error handling, type safety/newtypes/validated constructors,
   exhaustive matching, async rules incl. blocking in async, locks across await,
   cancel-safety annotations that are wrong, Drop of async resources, API design).
4. AI-worker anti-patterns: copy-paste duplication that drifts, speculative abstraction or
   generality, dead or test-only code shipped in production, comments that restate code or
   lie, review-process labels in code ("round 17", "F3-N73", "todo 37"), defensive checks
   inside trusted code, swallowed or downgraded errors, string matching on error names or
   Debug output, magic numbers repeated across files, oversized god-modules, `#[expect]`
   used to paper over a design problem, wildcard arms hiding variants, misleading names,
   needless clones/allocations, stringly-typed APIs.
5. Test quality for tests in your scope: tests that cannot fail, mock-echo, fixed sleeps,
   prose pins, Debug-format assertions, duplicated scenarios.

## Not findings

- Idioms the lint profile mandates (e.g. `drop(map.insert(..))` for `unused_results`,
  `let _: T = ..`, `#[inline]` on public items, doc comments on private items, `#[expect]`
  with a reason where the lint is genuinely a false positive).
- Items already listed in `docs/BACKLOG.md` (read it). If you think a BACKLOG item is
  more severe than it says, report it tagged KNOWN-BACKLOG.
- Owner decisions: operators may apply (the recovery timer runs under the protected
  change's permission); recovery-mode rule (router -> fail-safe timer, extender/ap/repeater
  -> scheduled reboot, unknown reported mode -> refuse, unreported mode -> timer only when
  `show last-change` reports a boolean `fail-safe.active`); audit entries wait for the
  cross-process lock and are written later; config-file routers read operator files while
  Web/CLI-managed credentials are sealed; secret files readable by group/others refused.

## Severity

- critical: unauthenticated code execution, full state/secret disclosure, takeover.
- high: a security control fully defeated with real consequences (authz bypass, secret
  disclosure to a lower-trust principal, stored XSS), or a bug causing router lockout,
  data loss, a wrong router command, or a main flow failing.
- medium: a real bug on an uncommon path, a weakened control, or a guideline violation
  with clear maintenance or correctness cost.
- low: minor quality issue with a concrete cost.
- info: worth knowing, no action required.

## Output (return this as your final answer, complete)

For each finding:

```
### <LANE>-<NN> <short title>
- severity: critical|high|medium|low|info
- kind: bug|security|guideline|anti-pattern|dead-code|duplication|test-quality|docs
- rule: RUST_GUIDELINES.md §<n> "<rule title>" (line) | overlay <file> "<rule>" | project rule (<x>) | none
- evidence: <path:lines> + quoted code
- impact: <concrete scenario and consequence>
- fix: <smallest effective change>
- confidence: high|medium|low (INFERRED: ...)
```

Order by severity. Report every high/critical; cap the rest at about 30 findings, merging
repeated instances of one pattern into a single finding listing all locations. End with:
`## Coverage` (files read in full, files skimmed, files not read) and `## Clean` (areas you
checked and found sound, one line each).
