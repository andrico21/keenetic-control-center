
## [2026-11-20] Todo 7
- A repair entry written by an append whose event write then fails is durable but not broadcast (append_locked returns
  the error; the writer stops and `is_alive` turns false). Kept as in the plan; the notifier sees the writer failure instead.

## [2026-11-19] Todo 2 (n2): jiff intake
- jiff 1.0.0 taken (cargo add at 2026-11-19T21:29Z under the 3-day cooldown; 1.0.1 was 45 h old, skipped by cargo). jiff-core/jiff-static/jiff-tzdb 1.0.0, portable-atomic-util 0.2.8 come with it. xtask raised 0.2.45 -> 1.0.0; its call site moved: `Timestamp::to_zoned` is `to_zoned_datetime` in 1.0.
- jiff 1.0 renamed `Zoned` to `ZonedDateTime`: the plan's clippy entry `jiff::Zoned::now` would be an invalid (silently ignored) path, so the entry is `jiff::ZonedDateTime::now`. Added `jiff::civil::Date::in_tz` too (also reads the global db). All 9 entries proven to bite by a scratch fn in kcc-app (clippy: 9x "use of a disallowed method"), scratch removed.
- cargo vet main: imports cover portable-atomic-util (bytecode-alliance, imports.lock updated); exemptions added for jiff, jiff-core, jiff-static, jiff-tzdb 1.0.0 (add-exemption). xtask: add-exemption jiff/jiff-core/jiff-static 1.0.0 (must run from xtask/ dir: add-exemption refuses --manifest-path), then `cargo vet prune --no-imports --no-audits` removed only the now-stale 0.2.45/0.1.7 jiff exemptions, syn 2.0.119 (left the xtask lock) and portable-atomic-util (now covered by the import).
- WeeklyTime/ZoneName also got serde (ZoneName deserializes through parse, WeeklyTime through new with deny_unknown_fields) for todo 6's schedules.json; DaySet serializes Monday first.
