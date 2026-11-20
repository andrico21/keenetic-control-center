
## [2026-11-20] Todo 12 (n12): one request reached the real api.telegram.org
- During a manual QA session of `kcc notify` the worker ran `kcc notify test` with a `kcc.toml` that had no
  `[notify.telegram]` table, so the default `https://api.telegram.org` was used: ONE `sendMessage` request with a random,
  never-issued token (built from /dev/urandom) went to the real Telegram, which answered 401 (`token_rejected`). No real
  token, chat or data was involved. Rule breach ("never contact the real Telegram"), reported. Manual QA of `notify test`
  must set `[notify.telegram] api_url` to a FakeTelegram (`kcc-fake-sinks`) first.

## [2026-11-20] Todo 10 (n10)
- The plan's API line says `NotifyHandle { report(line), ... }`; the scheduler needs the event filter and the message language, so `report` takes `(NotifyEvent, FnOnce(Locale) -> String)`. Todo 13 must adapt.
- Job failures are reported after the merge window (30 s) so the scheduler can claim its job ids first; a job whose Failed event is broadcast twice within that window is reported once.
- Router lockout: if the account's lockout window already ended when the notifier reads users.json (only possible when the notifier is far behind), no message is sent.
- Worker slip: one `git checkout <file>` was used in the worktree to undo my own edit of crates/kcc/src/server_error.rs (no other file touched, no index change).
