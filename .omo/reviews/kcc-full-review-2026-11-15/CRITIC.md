# Critic brief: validate review findings (read-only)

Repository: `/home/andrico/keenetic-control-center`, HEAD `349b7fb`. A reviewer produced
the findings below. Your job is to try to FALSIFY each one, independently, from the code.

## Rules

- READ-ONLY. Never edit files. Do not run `cargo`. Use read/grep/rg/sed/git only.
- Open every cited `path:line` yourself in THIS session. Do not trust the reviewer's
  quotes, line numbers or reasoning; re-derive the behaviour from the code.
- For each finding ask:
  1. Does the cited code exist and say what the finding claims?
  2. Is the failure path actually reachable (callers, guards elsewhere, type invariants,
     config validation, route/permission layers, the SDK's real behaviour)?
  3. Is it mandated by the lint profile (`RUST_GUIDELINES.md` §9 "Satisfying the
     profile", around lines 2038-2140), an owner decision (see below), or an item already
     in `docs/BACKLOG.md`? Then it is not a new finding.
  4. Does the cited guideline rule (`docs/rust-guidelines/RUST_GUIDELINES.md`, overlays)
     really say that? Quote the rule line if you rely on it.
  5. Is the severity right for the demonstrated consequence (scale below)?
- Owner decisions (not findings): operators may apply, the recovery timer runs under the
  protected change's permission; recovery-mode rule (router -> fail-safe timer;
  extender/ap/repeater -> scheduled reboot; unknown reported mode -> refuse; unreported
  mode -> timer only when `show last-change` reports a boolean `fail-safe.active`); audit
  entries wait for the cross-process lock and are written later; config-file routers read
  operator files while Web/CLI-managed credentials are sealed; secret files readable by
  group/others are refused.
- Severity: critical (unauth RCE/full secret disclosure/takeover), high (security control
  fully defeated with real consequences, or router lockout/data loss/wrong router
  command/main flow broken), medium (real bug on uncommon path, weakened control, or
  guideline violation with clear cost), low (minor quality with concrete cost), info.

## Output (return as your final answer, complete)

For each finding id, in order:

```
### <ID> <VERDICT: CONFIRMED | ADJUSTED | REFUTED | DUPLICATE-OF <ID>>
- checked: <path:lines you opened>
- reasoning: <2-6 sentences; for REFUTED say exactly what makes it wrong>
- severity: <final severity if CONFIRMED/ADJUSTED>
- correction: <for ADJUSTED: the corrected claim, evidence or fix>
```

End with `## Summary`: counts per verdict and any new issue you noticed while checking
(label it NEW, with evidence; it will be validated separately).
