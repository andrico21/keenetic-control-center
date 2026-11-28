# kcc-live-readiness: problems (append-only; unresolved blockers)

## [2026-11-26] Todo 5: acceptance gap (fake-router request log)
- The CLI acceptance "nothing sent to the fake router (its request log is empty)" is not covered by a test. The unit tests drive `typed` through the injectable prompt (mismatch gives exit 2 with `cli-secret-mismatch` and returns no secret). Every caller reads the new secret with `?` before it builds or sends the change. But all six router callers call `new_secret` after `Session::open`, which signs in and reads the router. So after a mismatch the fake's log would hold the sign-in and read requests, though never the change. An empty log needs either the prompt moved before `Session::open` in each caller (then a permission or protected-account refusal would come after the user has typed twice) or a prompt seam on `Ctx` (a production seam only tests need). Not done; owner or orchestrator to decide.
- `crates/kcc-web/src/auth.rs` was already about 573 pure LOC before todo 5, over the 250 limit; todo 5 adds 7 lines.

## [2026-11-27] Todo 12: real capture blocked by the capture self-check (exit 3)
- `kcc-capture` against the owner's router (read-only, protocol followed) exited 3: "self-check found a host identifier in manifest.json; the capture was deleted". No capture directory, no identifiers.txt. The protocol forbids a retry with a weaker tool, so the harness red run against real shapes is not done. Most likely the recorded residual R1: a learned host value equal to an interface id inside a `show-interface-stat-<id>` manifest item name (the manifest scan covers those names on purpose). Needs an orchestrator/owner decision: e.g. name interface-stat items by index (`show-interface-stat-<n>`) or alias the interface id in the item name, then re-run todo 12's capture. Blocks the real-shape work of todos 13-22 and 28.

## [2026-11-27] Todo 12 round 2: capture still blocked (exit 3), now diagnosed
- The round-1 blocker line above is superseded. With value-free diagnostics, run 2 exited 3 on two causes:
  - (1) a firmware interface id in a `show-interface-stat-*` manifest item name. Fixed by the C1 manifest exemption, with tests, but not yet proven on the router.
  - (2) three learned route comments (`rci-root.ip.route[n].comment`) left in running-config.txt by the config anonymizer. This is a data-file finding, so it is not fixed by rule.
- Proposed: make `Anonymizer::config` also replace learned values across each printed line (multi-word values). After that, one capture run remains.
- Fidelity concern (not a leak): the interface id of (1) was learned as a host name from a hotspot host's `interface` object. The anonymizer therefore rewrites that id to `host-N` in every data file, which breaks replay of interface-keyed answers. A narrow learning rule may be wanted, but the key is masked in the diagnostics, so it is not classified with certainty.

## [2026-11-27] Todo 12 round 3
- RESOLVED: kcc-capture exit 3 on the owner's router. Run 3 exited 0 after the config whole-text replacement and the interface-reference learning rule; the capture is in `.omo/evidence/live/KN-1811-5.1.10/`.
- OPEN: the harness replay leaves rc roots the router refused out of its answer, so `live_vpn_servers` passes vacuously (4 of 6 roots refused with `Core::Configurator`). Option: replay a refused rc root as the same router error (the manifest only keeps a Debug string today, so a structured skip record would be needed). Decide in todo 24 or the orchestrator.
- OPEN: `live_nat_sessions` decodes the real capture, against the plan's expectation, so todo 17 may have less to fix than planned.

## [2026-11-27] Todo 12 round 4
- RESOLVED: the run-3 capture's key paths were not the router's (learned generic words rewritten inside firmware keys and config keywords). Run 4 was taken with the vocabulary rule, the substring guard and the new fidelity check (exit 4); embedded alias keys 651 -> 0. Todos 13-22 and 28 should copy key paths from the run-4 capture only; `defective-run3-KN-1811-5.1.10/` is kept locally for comparison and must not be used for fixtures.
- OPEN (unchanged): the harness replay leaves refused rc roots out, so `live_vpn_servers` passes vacuously; `live_nat_sessions` decodes the real capture.
- OPEN (residual of the rule): a router value equal to a vocabulary word is now kept verbatim in the capture (by design). A schema key counts from 3 objects; an owner-chosen name used as a key in 3 or more non-name-keyed objects would count as a firmware word. Name-keyed maps (users, schedules) are excluded structurally; no other such map was seen in run 4.
- Precision for the line above: what was verified in run 4 is that the 3 words dropped from identifiers.txt each entered the vocabulary through a legitimate source (one a key in 561 objects and a config command word, one a key in 5 objects, one a request word), and that no remaining identifier equals a key found in 3+ objects of the written capture. No full audit of every name-keyed map of the firmware was done.

## [2026-11-28] Todo 12 round 5
- Resolved: D1 (an owner name counted as vocabulary through name-keyed maps), D2 (untested secret/serial/text-rule guards), D3 (fidelity masked every non-vocabulary key; counts missing). The run-4 capture is set aside (`defective-run4-KN-1811-5.1.10/`); the current capture is run 5.
- Residual, by design: a learned name that sits as the key of a map kcc does not know as name-keyed is NOT rewritten any more; the self-check refuses such a run (exit 3) instead. On the owner's router no such key exists today (run 5 exit 0). A new name-keyed map found that way is added to `names_below`.
- Residual: kcc-capture's tracing has no per-request filter (tracing-subscriber without env-filter), so the kcc-capture lines of agent-actions.log are reconstructed from the tool's fixed request set (request code unchanged since run 2); the serial-script lines are logged live.
