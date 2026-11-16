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

## [2026-11-16] Todos 3 and 5 committed (b57d6e9, 59a18c4); workers 4 and 8 started
- Workers r4 and r8 are cut from the temporary base 258998a = master 757b48b + todos 3 and 5; that tree equals master 59a18c4 on product paths. Their patches MUST be generated with `git diff --binary 258998a wt/rN -- <product paths>` (never against master with a different base).
- Golden HTML baseline: to be captured on master after todo 8 lands and before todo 10 starts (no template changed in todos 1-7).

## [2026-11-16] Todo 8 split (decision)
- Worker r8 finished C-07 and D-15 (ValidatedRequest.value read-only, ChangeOp.commands/push) and found B-08 (strict CliCommand::new binding line<->request through the catalog grammar) not shippable: it refuses real lines of ~33 command paths (request shapes that do not encode the line, e.g. `access-list rule N disable` with {index}; leading-group and argument-spelling gaps; cleanup lines `no ip policy X` paired with an unrelated request). Inventory in .omo/evidence/task-8-kcc-review-fixes-b08-attempt.log.
- Decision: B-08 is NOT dropped. Todo 8 is committed as the immutability part once the KeenDNS host-name regression is fixed (follow-up worker 8c in the same worktree); B-08 gets its own deep-high worker scheduled after todo 41 (catalog typed arguments and grammar fixes overlap) and its own commit; the todo 8 checkbox is ticked only when B-08 is closed. The funnel 8 -> 9/10 -> 11 -> 12 is not blocked on B-08: todo 9 uses CliCommand::new for word validation, not grammar binding. To be disclosed to the owner as a plan deviation (a todo closed in two commits).

## [2026-11-16] Commits 9eedbb7 (todo 8 part 1), b7e853d (todo 9), 95a9b4f (todo 10); B-08 dispatched early
- Gate fx5 (todos 8, 9, 10 together) was green except one test: the anonymizer guard flagged a MAC in the todo 8 follow-up test (`02:00:5e:...`), fixed by a quick worker to `02:00:00:00:53:43` and re-verified (no_secrets, fmt). Committed per todo from three patches (r8 vs 258998a, r9/r10 vs 58b76e9, applied with --3way for the shared CHANGELOG hunks); product tree equals the gated tree.
- Todo 8 stays unticked: B-08 (strict CliCommand::new binding) runs now as its own deep-high worker (wt/r8b, base 95a9b4f) because the capacity is idle and only todo 11 -> 12 is unblocked; it will land as its own commit and then tick todo 8.
- Dependency note: the matrix funnels everything through 12 (13 and 20 both need it); after 11 only 12 can run, then W3 fans out.

## [2026-11-16] Todo 8 part B-08 (wt/r8b) design
- One binding check, in kcc-catalog (`ValidatedRequest::renders_cli`, shared grammar with `validate_cli`), called by the only two literal constructors `CliCommand::new`/`secret` (now fallible, `SecretCommandError::Line`, new variant: no existing one says "line does not render its request"). No unchecked constructor.
- Drift is fixed at the planner by pairing each line with the request that describes it (segments carry a create and a delete request per step; `interface down`; static lease `{host, ip}`; firewall `new-index`), or by rendering the documented form (IPv6 route interface-before-gateway, DNS filter-profile description). Grammar gaps are fixed at the catalog source (generator bare-word promotion, `catalog/synopsis-errata.json`) or in the one shared matcher (leading group, keyword-subsequence parent, repeated synopsis lines, `a:b` join, `no` + positive form).
- `interface vlan-id` exists only as an erratum; migration keeps refusing `vlan-id` lines to keep its behaviour (owner decision to change).

## [2026-11-16] Commits e623772 (todo 11) and 034ec91 (todo 8 part B / B-08); todo 8 ticked
- Gate fx6 was green except one test again: the repository guard flagged an RFC1918 literal in the prose "reason" of catalog/synopsis-errata.json (a quote of the manual's example). A small worker reworded the string (the generator never reads `reason`), no_secrets 2 passed. Lesson for later worker prompts: workers' targeted checks skip kcc-testkit's no_secrets guard, so every worker prompt now says "no IP literals except RFC 5737, MACs 02:00:00:00:XX:YY, also in prose, JSON and docs" (kcc-agent-rules.md updated).
- Not proven on hardware (for the final report / BACKLOG): the ipv6 route argument order (interface before gateway), `ip route` metric on 4.3, `<address> <port>` vs `<address>:<port>` for `system log server` and `wireguard peer endpoint`, `interface down`, the `vlan-id` line, the new fqdn-typed `ip http proxy upstream` host name.
