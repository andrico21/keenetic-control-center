# issues - kcc-review-fixes (append only)

## [2026-11-16] Todo 3 (wt/r3) out-of-scope notes
- `crates/kcc-migrate/src/rules.rs` was 620 pure LOC before todo 3 (now 656), far over the ~250 ceiling; a split by responsibility (rule loading / classification / mapping+conflict helpers) is a follow-up refactor, not done here.
- Remapped (`remap-mapped-reference`) lines still skip the scalar-conflict check, like before; only copy-rule lines (secrets, keys) gained it in todo 3.

## [2026-11-16] Orchestrator slip while merging todos 3 and 5 (disclosed, no harm)
- I generated the r3/r5 patches with `git diff master wt/rN` although the worktrees were cut from a040ba2 and master had moved to 757b48b (todos 2 and 7). The patches therefore carried the reverse of todos 2 and 7; the r3 patch applied cleanly, giving an index with those two todos reverted. I noticed from the `git diff --cached --stat` (32 files, 875 deletions) and the r5 apply errors before any gate or commit ran, restored the index and tree to HEAD (`git reset`, `git checkout -- <product paths>`, removed the one untracked file), deleted the two temporary worktrees/targets built on the wrong base, and regenerated the patches against each worktree's own base (`git diff --binary a040ba2 wt/rN`). Rule: always diff against the worker's base commit, not master.

## [2026-11-16] Todo 8: B-08 strict line binding escalated (deep-high)
- A strict `CliCommand::new(line, request) -> Result` that binds the line to the request through the catalog grammar (attempt and refusal inventory: `.omo/evidence/task-8-kcc-review-fixes-b08-attempt.log`) refuses current lines of ~33 command paths in kcc-domain alone (65 failing tests): real drift (segments cleanup pairs `no interface X`, `no ip policy X`, `no ip dhcp pool X` with unrelated requests; `interface X vlan-id N` paired with the `interface` request; firewall `rule N disable` with `{index}`), router spellings the grammar lacks (`interface X down` for `interface up` no; `address port` where the synopsis has `address:port`), and generator shapes (`access-list permit|deny` protocol keyword, `ip dhcp host` single `host` arg, `(vpn-server)`/`(ndns)`/`(system)` leading groups, `show *` with `(show)` group, `access-list rule` without `new-index`). Not shipped; decision needed on scope (site-by-site migration + catalog grammar fixes overlapping todo 41) before `new` can become fallible.

## [2026-11-16] Todo 9 (wt/r9) out-of-scope notes
- `kcc-domain/src/dns/change.rs` was 363 pure LOC before todo 9 (393 after the token checks): a split (catalog input / line rendering) is a follow-up refactor.
- `policies::change::plan::description(name, None)` builds `{"no":true}`, but `render::expected_leaf` requires a `description` field, so clearing a policy description fails with InvalidResponse (pre-existing, untouched).
- The Web schedule dialog still holds descriptions to one word (`is_word`); the domain now quotes them, so allowing spaces there needs only a new help/error key (follow-up).
- The fake router has no `dns-proxy filter profile description` / `object-group fqdn description` grammar.

## [2026-11-16] Todo 10 (wt/r10) follow-ups, not fixed here
- Secret pages (`wan_password`, `wifi_psk`, `vpn_credential`, `vpn_server` psk) pass `Params::default()`: if their plan ever reaches Management (todo 11 classifies WAN planners; a WAN password on the management WAN), the kit's dialog resubmits without the typed secret and the confirmed request answers "unchanged". Such a page needs its own in-dialog confirmation plus `.confirmed_by_page(Risk::Management)`, as `user_password::run` does. Todo 11 should check `wan_password`.
- Form-only handlers whose plans are Write today (dns forms and intercept, nat, routing route/policy, dhcp, schedules, system general edit, internet create, vpn forms/import) get a path-only `Resubmit`; if one of them can plan a management change later, it must read the query too (as segment create and vpn state/service now do) and pass `params.again(path)`.
- No Web test reaches the internet order/edit management path: the fake router cannot make a WAN carry kcc's connection; the kit unit test `asking_tests` covers any planned management change.
