# decisions - kcc-review-fixes (append only)

## [2026-11-15] Orchestration set-up
- Plan committed at 2099cd4 (plan, draft, review evidence). Boulder work kcc-review-fixes-ea2f0150 active; ledger goal entry written.
- Merge flow: worktree wt/rN from master, patch (git diff --binary master wt/rN) applied with `git apply --index` in the main checkout, G0 gate on the main target, one commit per todo. The main checkout is used for integration because tracked .omo state files cannot be committed from a side worktree without conflicts; every product diff is reviewed before it is applied. Disclosed.
- Capacity: at most 2 concurrent cargo builds (workers use CARGO_BUILD_JOBS=2); a gate counts as one build.
- Wave 1 first dispatch: todos 1 (H2) and 6 (masker seam). Next in the file-disjoint queue: 2, 3, then 4 (after 3), 5 (after 1), 7 (after 6).

## [2026-11-16] Todo 6
- Secret-name rule = union of MCP substrings + `passphrase` + Web exact names (`key`,`pin`,`community`) + suffix `_key`, after lowercasing and `-`->`_`. `authtoken`, `radiussecret`, `macpasswd`, `wpa-psk` fall out of the substring parts.
- C-04: `Interface.extra.authentication` is reduced to presence (`{name: true}`) rather than dropped, because the Web AP rows read password presence from it; every `ns3` member is dropped.
- `secrets::redact` keeps `Token::Ns3` with a `<redacted>` payload (shows `ns3 <redacted>`); `mask::redacted_config` prints the bare `<redacted>` word (download/backup/CLI form). Both are byte-identical to the deleted copies' output.

## [2026-11-16] Todos 1 and 6 reviewed; gate fx1 running on the combined tree
- Todo 6 behaviour changes to name in the commit body: MCP masks names ending `_key`/`-key` (so a WireGuard `public_key`/`public-key` member is masked on MCP; this follows from the plan's rule "Web is_secret with - and _ normalised" and is the safe direction); a secret member holding an object is replaced whole on the Web too; interface reads keep an `authentication` presence map and drop ns3 members; secrets::redact now masks every ns3 payload itself; anonymizer relies on redact for ns3 (still called first).
- Todo 7 is dispatched on a temporary base (commit 8953c9d = master + 1 + 6) so it sees the shared masker; its patch is applied after the fx1 commits land.
