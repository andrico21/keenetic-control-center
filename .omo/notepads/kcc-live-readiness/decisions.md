# kcc-live-readiness: decisions (append-only; every landed todo records its ACTUAL API here)

## [2026-11-26] Run notes from the owner (binding for the whole run)
- Delivery: each todo lands on master as the plan says; commit and push to origin master fast-forward only (never force, no history rewrite, no git config changes); after each push run `/home/andrico/ci-watch-start.sh <sha8>` (status in `/home/andrico/ci-watch.out`, `DONE` appended when CI and Container finish); a newer push cancels the running CI, so the last pushed commit must end green; a red run is a regression fixed before F1.
- Paths: every `.omo/evidence/...` path in the plan is `/home/andrico/keenetic-control-center/.omo/evidence/...` (owner-router.env, the live capture, identifiers.txt, the start sha, agent-actions.log, task logs); absolute paths always, `KCC_LIVE_CAPTURE_DIR` included.
- Builds: cargo only through `/home/andrico/kcc-cargo` (two build slots); remove each worktree after it lands; keep at least 80 GB free; scratch under /home/andrico, never /tmp.
- The plan and draft are untracked; they go into the first chore(omo) commit after the leak scan.
- The owner's router is read-only for the agent exactly as the plan's hardware protocol says; never contact an Entware host, Telegram or an identity provider.
