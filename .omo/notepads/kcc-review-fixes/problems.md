# problems - kcc-review-fixes (append only)

## G1 blocker found at gate fx34: cargo deny fails on new advisories (owner decision needed before F2)
- RUSTSEC-2026-0543 (chrono unmaintained) and RUSTSEC-2026-0542 (humantime wraps chrono, so also unmaintained; all versions affected, "No safe upgrade is available") appeared between fx33 (deny=0) and fx34. `deny.toml` sets unmaintained = "all" so `cargo deny check` fails; `cargo audit` lists them as allowed warnings. Todo 52 changed no manifest.
- humantime = "2.4.0" is a workspace dependency (humantime-serde reaches kcc-app, kcc-web, rmcp-server-kit); the chrono edge is transitive. Options: (a) replace humantime/humantime-serde in kcc with a crate already in Cargo.lock or hand parsing; (b) add a dated ignore with reason in deny.toml (loosens a gate: owner decision); (c) wait for upstream. G0 is unaffected; G1/F2 needs this resolved. Belongs with todos 71/75 (dependencies) or a decision by the owner.

## Owner questions from todo 68 (live suites)
1. Should the live migration SOURCE router need a profile marker? Today it is gated by the serial allowlist and the admitted outbound policy only. Marking it `test_device = true` would wrongly admit it to the write suites, so a separate read-only marker may be wanted.
2. The live migration probe writes after the rollback, under its own fail-safe timer (the plan's binding alternative); running it before the rollback would trip the change workflow's own conflict check.

## Still open after todo 72
- OWNER: cargo deny check (G1) fails on RUSTSEC-2026-0542 and -0543 (chrono and humantime unmaintained; deny.toml sets unmaintained = "all"). Not caused by any manifest change; no fixed version exists. Todo 75's acceptance and F2's G1 run need either (1) replacing humantime/humantime-serde with hand parsing (no new crate) or (2) a dated ignore with reason in deny.toml (loosens a gate).
