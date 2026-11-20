# kcc-entware-mcp: learnings (orchestrator)

READ FIRST: `.omo/notepads/kcc-notify-schedule/learnings.md` and `decisions.md` (macOS/Windows portability, paused-clock + Unix-socket seam, Windows launcher and de-elevated tests,
rustdoc private links, drain request bodies in fakes, job verdict vs `JobRunner::ended`, union-merge of shared docs, keys.rs regenerated not merged). They all still apply.
New for this plan:
- Never push for this plan until the owner says so (the earlier grant named the CI fix and kcc-notify-schedule). Commit locally per todo.
- A scheduled/unattended path that can leave the router's fail-safe timer armed must hold the router lease until the timer ran out (see decisions.md of kcc-notify-schedule, todo 21);
  the same invariant applies to every new write path of this plan (Entware drive initialize/setup job, SSH mutations, listener restarts are process-local but must never leave the main server down).
- `kcc-cargo xtask <sub>` that itself spawns cargo can hang (xtask inherits the wrapper's slot fds): run the built `debug/xtask` binary directly in that case; local-only problem.
- cargo-mutants needs `RUSTFLAGS=--cap-lints=warn CARGO_BUILD_WARNINGS=allow` (workspace has `unused = deny`).
- UPDATE (owner, this session): "yes, you can push to master" - pushes to origin master are authorized for kcc-entware-mcp (fast-forward only, never forced, after `git fetch -q origin` and
  `git merge-base --is-ancestor origin/master HEAD`; command `git -c credential.helper='!gh auth git-credential' push origin master`; batch pushes, a push cancels the in-progress CI of the same ref).
