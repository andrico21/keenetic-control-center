# issues - kcc-review-fixes (append only)

## [2026-11-16] Todo 3 (wt/r3) out-of-scope notes
- `crates/kcc-migrate/src/rules.rs` was 620 pure LOC before todo 3 (now 656), far over the ~250 ceiling; a split by responsibility (rule loading / classification / mapping+conflict helpers) is a follow-up refactor, not done here.
- Remapped (`remap-mapped-reference`) lines still skip the scalar-conflict check, like before; only copy-rule lines (secrets, keys) gained it in todo 3.

## [2026-11-16] Orchestrator slip while merging todos 3 and 5 (disclosed, no harm)
- I generated the r3/r5 patches with `git diff master wt/rN` although the worktrees were cut from a040ba2 and master had moved to 757b48b (todos 2 and 7). The patches therefore carried the reverse of todos 2 and 7; the r3 patch applied cleanly, giving an index with those two todos reverted. I noticed from the `git diff --cached --stat` (32 files, 875 deletions) and the r5 apply errors before any gate or commit ran, restored the index and tree to HEAD (`git reset`, `git checkout -- <product paths>`, removed the one untracked file), deleted the two temporary worktrees/targets built on the wrong base, and regenerated the patches against each worktree's own base (`git diff --binary a040ba2 wt/rN`). Rule: always diff against the worker's base commit, not master.
