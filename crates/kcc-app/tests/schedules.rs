//! Scheduled actions: role-checked store, owner stamping, limits and the run ledger.

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::{error::Error, slice};
    use std::{fs, sync::Barrier, thread};

    use kcc_app::{
        permissions::{Permission, Role},
        persist::{StateError, StateStore},
        schedules::{
            ledger::{RunError, RunLedger, RunOutcome, RunState, Trigger},
            model::{
                Action, NewSchedule, Owner, PauseReason, Schedule, ScheduleState,
                names::{ClientMac, PolicyName, PresetId, ScheduleName},
            },
            store::{ScheduleError, ScheduleStore},
            time::{DaySet, WeeklyTime, ZoneName},
        },
    };
    use serde_json::Value;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    /// The time every test starts at.
    const NOW: i64 = 1_800_000_000;

    fn state() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let store = StateStore::open(directory.path())?;
        Ok((directory, store))
    }

    fn role(permissions: &[Permission], scope: &[&str]) -> Role {
        Role::new(
            "custom".to_owned(),
            permissions.iter().copied(),
            scope.iter().map(|glob| (*glob).to_owned()).collect(),
        )
    }

    fn admin() -> Role {
        role(&Permission::ALL, &[])
    }

    fn web(username: &str) -> Owner {
        Owner::Web {
            username: username.to_owned(),
        }
    }

    fn weekly() -> Result<WeeklyTime, Box<dyn Error>> {
        Ok(WeeklyTime::new(
            DaySet::from_names(["mon", "fri"])?,
            8,
            30,
            ZoneName::parse("Europe/Berlin")?,
        )?)
    }

    fn new_schedule(
        name: &str,
        router: &str,
        action: Action,
    ) -> Result<NewSchedule, Box<dyn Error>> {
        Ok(NewSchedule::new(
            ScheduleName::parse(name)?,
            router.to_owned(),
            weekly()?,
            action,
        ))
    }

    fn policy_switch() -> Result<Action, Box<dyn Error>> {
        Ok(Action::PolicySwitch {
            mac: ClientMac::parse("02:00:00:00:00:0A")?,
            policy: PolicyName::parse("Policy0")?,
        })
    }

    fn preset() -> Result<Action, Box<dyn Error>> {
        Ok(Action::Preset {
            preset_id: PresetId::parse("evening")?,
            ack_documentation_tier: false,
        })
    }

    fn create(
        store: &ScheduleStore,
        name: &str,
        router: &str,
        action: Action,
    ) -> Result<Schedule, Box<dyn Error>> {
        Ok(store.create(
            &admin(),
            new_schedule(name, router, action)?,
            web("alice"),
            NOW,
        )?)
    }

    /// todo 6: create, update and resume stamp the acting owner and `updated_at`, and
    /// advance the ledger so no slot at or before the change fires.
    #[test]
    fn create_update_and_resume_restamp_the_owner() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state.clone());
        let ledger = RunLedger::new(state);
        let created = create(&store, "night", "home", Action::Backup)?;
        assert_eq!(created.id.len(), 16, "id {}", created.id);
        assert!(
            created
                .id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "id {}",
            created.id
        );
        assert_eq!(created.owner.to_string(), "web:alice", "creator");
        assert!(
            matches!(
                ledger.begin(&created.id, Trigger::Slot(NOW), NOW),
                Err(RunError::AlreadyFired)
            ),
            "a slot at the creation time never fires"
        );

        let updated = store.update(
            &admin(),
            &created.id,
            new_schedule("night", "home", Action::Reboot)?,
            Owner::Cli {
                os_user: "bob".to_owned(),
            },
            NOW + 100,
        )?;
        assert_eq!(updated.owner.to_string(), "cli:bob", "editor");
        assert_eq!((updated.created_at, updated.updated_at), (NOW, NOW + 100));
        assert_eq!(updated.action, Action::Reboot, "edited action");
        assert!(
            matches!(
                ledger.begin(&created.id, Trigger::Slot(NOW + 100), NOW + 100),
                Err(RunError::AlreadyFired)
            ),
            "a slot at the edit time never fires"
        );

        let paused = store.pause(&admin(), &created.id, NOW + 200)?;
        assert_eq!(
            paused.state,
            ScheduleState::Paused {
                reason: PauseReason::Manual,
                at: NOW + 200
            }
        );
        assert_eq!(
            paused.owner.to_string(),
            "cli:bob",
            "pausing keeps the owner"
        );
        let resumed = store.resume(&admin(), &created.id, web("carol"), NOW + 300)?;
        assert_eq!(resumed.state, ScheduleState::Active, "resumed");
        assert_eq!(resumed.owner.to_string(), "web:carol", "resumer");
        assert_eq!(resumed.updated_at, NOW + 300, "resume time");
        assert!(
            matches!(
                ledger.begin(&created.id, Trigger::Slot(NOW + 250), NOW + 300),
                Err(RunError::AlreadyFired)
            ),
            "a slot missed while paused never fires"
        );
        assert_eq!(
            ledger.begin(&created.id, Trigger::Slot(NOW + 400), NOW + 400)?,
            NOW + 400,
            "a later slot fires"
        );
        assert_eq!(store.get(&admin(), &created.id)?, resumed, "stored");
        Ok(())
    }

    /// todo 6: every role path needs `ManageSchedules`, the action's permissions on the
    /// router and the router in scope.
    #[test]
    fn roles_without_the_needed_permissions_or_scope_are_refused() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state);
        let alice = || web("alice");
        let without_manage = role(&[Permission::Read, Permission::Write], &[]);
        assert!(matches!(
            store.create(
                &without_manage,
                new_schedule("a", "home", Action::Backup)?,
                alice(),
                NOW
            ),
            Err(ScheduleError::Forbidden)
        ));
        assert!(matches!(
            store.list(&without_manage),
            Err(ScheduleError::Forbidden)
        ));

        let writer = role(&[Permission::ManageSchedules, Permission::Write], &["home"]);
        assert!(matches!(
            store.create(
                &writer,
                new_schedule("a", "home", Action::Reboot)?,
                alice(),
                NOW
            ),
            Err(ScheduleError::Forbidden)
        ));
        assert!(matches!(
            store.create(
                &writer,
                new_schedule("a", "lab", Action::Backup)?,
                alice(),
                NOW
            ),
            Err(ScheduleError::Forbidden)
        ));
        let backup = store.create(
            &writer,
            new_schedule("a", "home", Action::Backup)?,
            alice(),
            NOW,
        )?;
        let reboot = create(&store, "b", "home", Action::Reboot)?;
        let elsewhere = create(&store, "c", "lab", Action::Backup)?;
        assert!(matches!(
            store.delete(&writer, &reboot.id),
            Err(ScheduleError::Forbidden)
        ));
        assert!(matches!(
            store.get(&writer, &elsewhere.id),
            Err(ScheduleError::NotFound)
        ));
        let listed = store
            .list(&writer)?
            .into_iter()
            .map(|schedule| schedule.id)
            .collect::<Vec<_>>();
        assert_eq!(listed.len(), 2, "only routers in scope: {listed:?}");
        assert!(!listed.contains(&elsewhere.id), "{listed:?}");
        store.delete(&writer, &backup.id)?;
        assert!(matches!(
            store.get(&admin(), &backup.id),
            Err(ScheduleError::NotFound)
        ));
        Ok(())
    }

    /// todo 6: a preset schedule also needs `Read` and `Migrate` on the preset's source.
    #[test]
    fn a_preset_whose_source_router_is_out_of_scope_is_refused() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state);
        let target_only = role(
            &[
                Permission::ManageSchedules,
                Permission::Read,
                Permission::Migrate,
                Permission::Write,
                Permission::Save,
            ],
            &["home"],
        );
        let from_lab = new_schedule("evening", "home", preset()?)?.with_preset_source("lab");
        assert!(matches!(
            store.create(&target_only, from_lab, web("alice"), NOW),
            Err(ScheduleError::Forbidden)
        ));
        let from_home = new_schedule("evening", "home", preset()?)?.with_preset_source("home");
        let created = store.create(&target_only, from_home, web("alice"), NOW)?;
        assert_eq!(created.router, "home", "accepted with the source in scope");
        let without_save = role(
            &[
                Permission::ManageSchedules,
                Permission::Read,
                Permission::Migrate,
                Permission::Write,
            ],
            &["home"],
        );
        assert!(matches!(
            store.create(
                &without_save,
                new_schedule("other", "home", preset()?)?,
                web("alice"),
                NOW
            ),
            Err(ScheduleError::Forbidden)
        ));
        Ok(())
    }

    /// todo 6: at most 64 schedules per router and 256 in total.
    #[test]
    fn the_65th_per_router_and_the_257th_in_total_are_refused() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state);
        for router in ["r0", "r1", "r2", "r3"] {
            for index in 0..64_u32 {
                drop(create(
                    &store,
                    &format!("s{index}"),
                    router,
                    Action::Backup,
                )?);
            }
        }
        assert!(matches!(
            create(&store, "s64", "r0", Action::Backup).map_err(|error| error.to_string()),
            Err(message) if message == ScheduleError::RouterLimit.to_string()
        ));
        assert!(matches!(
            create(&store, "s0", "r4", Action::Backup).map_err(|error| error.to_string()),
            Err(message) if message == ScheduleError::TotalLimit.to_string()
        ));
        assert_eq!(store.list(&admin())?.len(), 256, "nothing was added");
        Ok(())
    }

    /// todo 6: names are unique per router.
    #[test]
    fn a_duplicate_name_on_one_router_is_refused() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state);
        let first = create(&store, "night", "home", Action::Backup)?;
        assert!(matches!(
            store.create(
                &admin(),
                new_schedule("night", "home", Action::Reboot)?,
                web("alice"),
                NOW
            ),
            Err(ScheduleError::DuplicateName)
        ));
        let second = create(&store, "other", "home", Action::Backup)?;
        assert!(matches!(
            store.update(
                &admin(),
                &second.id,
                new_schedule("night", "home", Action::Backup)?,
                web("alice"),
                NOW
            ),
            Err(ScheduleError::DuplicateName)
        ));
        drop(store.update(
            &admin(),
            &first.id,
            new_schedule("night", "home", Action::Reboot)?,
            web("alice"),
            NOW,
        )?);
        drop(create(&store, "night", "lab", Action::Backup)?);
        Ok(())
    }

    /// todo 6: names, MACs and policies are parsed at the boundary.
    #[test]
    fn names_macs_and_policies_are_parsed() -> TestResult {
        assert_eq!(
            ClientMac::parse("02-00-00-00-AB-CD")?.as_str(),
            "02:00:00:00:ab:cd"
        );
        assert!(ClientMac::parse("02:00:00:00:ab").is_err(), "short MAC");
        assert!(ClientMac::parse("02:00:00:00:ab:cg").is_err(), "not hex");
        assert!(PolicyName::parse("Policy 0").is_err(), "space");
        assert!(PolicyName::parse(&"p".repeat(65)).is_err(), "65 chars");
        assert!(ScheduleName::parse("").is_err(), "empty name");
        assert!(ScheduleName::parse(&"n".repeat(65)).is_err(), "65 chars");
        assert!(ScheduleName::parse("line\nbreak").is_err(), "control char");
        assert!(PresetId::parse("../x").is_err(), "path");
        Ok(())
    }

    /// Adds `"extra": true` to the first object at `pointer` of state file `file`.
    fn inject_unknown_field(state: &StateStore, file: &str, pointer: &str) -> TestResult {
        let path = state.dir().join(file);
        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let target = document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or("no object at the pointer")?;
        drop(target.insert("extra".to_owned(), Value::Bool(true)));
        fs::write(&path, serde_json::to_vec(&document)?)?;
        Ok(())
    }

    /// todo 6: both documents refuse unknown fields.
    #[test]
    fn unknown_fields_are_refused() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state.clone());
        let ledger = RunLedger::new(state.clone());
        let created = create(&store, "night", "home", policy_switch()?)?;
        inject_unknown_field(
            &state,
            "schedule_runs.json",
            &format!("/schedules/{}", created.id),
        )?;
        assert!(matches!(
            ledger.begin(&created.id, Trigger::Slot(NOW + 60), NOW + 60),
            Err(RunError::State(StateError::Corrupt { file: _, reason: _ }))
        ));
        inject_unknown_field(&state, "schedules.json", "/schedules/0/action")?;
        assert!(matches!(
            store.list(&admin()),
            Err(ScheduleError::State(StateError::Corrupt {
                file: _,
                reason: _
            }))
        ));
        Ok(())
    }

    /// todo 6: a slot fires at most once and never before a later one.
    #[test]
    fn begin_refuses_a_fired_or_earlier_slot() -> TestResult {
        let (_directory, state) = state()?;
        let ledger = RunLedger::new(state);
        assert_eq!(ledger.begin("aa", Trigger::Slot(NOW), NOW)?, NOW);
        assert!(matches!(
            ledger.begin("aa", Trigger::Slot(NOW), NOW + 1),
            Err(RunError::AlreadyFired)
        ));
        assert!(matches!(
            ledger.begin("aa", Trigger::Slot(NOW - 60), NOW + 2),
            Err(RunError::AlreadyFired)
        ));
        let now = || Trigger::Now {
            requested_by: "web:alice".to_owned(),
        };
        assert_eq!(ledger.begin("aa", now(), NOW + 3)?, NOW + 3);
        assert_eq!(ledger.begin("aa", now(), NOW + 4)?, NOW + 4);
        ledger.skip("aa", NOW + 600, "late", NOW + 700)?;
        assert!(
            matches!(
                ledger.begin("aa", Trigger::Slot(NOW + 600), NOW + 701),
                Err(RunError::AlreadyFired)
            ),
            "a skipped slot counts as fired"
        );
        let runs = ledger.runs("aa")?;
        assert_eq!(runs.len(), 4, "{runs:?}");
        assert_eq!(
            runs.last().map(|run| (&run.state, run.slot)),
            Some((
                &RunState::Skipped {
                    reason: "late".to_owned()
                },
                Some(NOW + 600)
            ))
        );
        Ok(())
    }

    /// todo 6: two runners racing for one slot: exactly one begins it.
    #[test]
    fn concurrent_begins_of_one_slot_admit_exactly_one() -> TestResult {
        let (_directory, state) = state()?;
        let barrier = Barrier::new(2);
        let results = thread::scope(|scope| {
            let racers = [0_i64, 1_i64].map(|offset| {
                let ledger = RunLedger::new(state.clone());
                let start = &barrier;
                scope.spawn(move || {
                    let _leader = start.wait();
                    ledger.begin("race", Trigger::Slot(NOW), NOW + offset)
                })
            });
            racers.map(|racer| racer.join().map_err(|_panic| "racer panicked"))
        });
        let mut won = 0_u32;
        for result in results {
            match result? {
                Ok(_) => won += 1,
                Err(RunError::AlreadyFired) => {}
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(won, 1, "exactly one racer begins the slot");
        assert_eq!(RunLedger::new(state).runs("race")?.len(), 1, "one record");
        Ok(())
    }

    /// todo 6: a server start marks every started run interrupted and reports them; a
    /// run marked so still ends with its true outcome.
    #[test]
    fn interrupted_runs_are_reported_and_finish_sets_the_true_outcome() -> TestResult {
        let (_directory, state) = state()?;
        let ledger = RunLedger::new(state);
        let slot = ledger.begin("aa", Trigger::Slot(NOW), NOW)?;
        let manual = ledger.begin(
            "bb",
            Trigger::Now {
                requested_by: "cli:bob".to_owned(),
            },
            NOW + 1,
        )?;
        let done = ledger.begin("cc", Trigger::Slot(NOW), NOW)?;
        ledger.finish(
            "cc",
            done,
            RunOutcome::Failed {
                code: "router_unreachable".to_owned(),
            },
            None,
            NOW + 5,
        )?;
        let mut interrupted = ledger.interrupt_started(NOW + 10)?;
        interrupted.sort();
        assert_eq!(
            interrupted,
            [("aa".to_owned(), Some(NOW)), ("bb".to_owned(), None)]
        );
        assert_eq!(ledger.interrupt_started(NOW + 11)?, [], "reported once");
        assert_eq!(
            ledger.runs("aa")?.first().map(|run| run.state.clone()),
            Some(RunState::Interrupted)
        );
        ledger.finish(
            "bb",
            manual,
            RunOutcome::Succeeded {
                unsaved: true,
                checksum: Some("abc".to_owned()),
            },
            Some("job-1".to_owned()),
            NOW + 20,
        )?;
        let finished = ledger.runs("bb")?;
        let run = finished.first().ok_or("no run")?;
        assert_eq!(
            run.state,
            RunState::Succeeded {
                unsaved: true,
                checksum: Some("abc".to_owned())
            }
        );
        assert_eq!(
            (
                run.finished_at,
                run.job_id.as_deref(),
                run.requested_by.as_deref()
            ),
            (Some(NOW + 20), Some("job-1"), Some("cli:bob"))
        );
        assert!(
            matches!(
                ledger.finish(
                    "aa",
                    slot + 1,
                    RunOutcome::Skipped {
                        reason: "router_busy".to_owned()
                    },
                    None,
                    NOW
                ),
                Err(RunError::NotFound)
            ),
            "no run started then"
        );
        Ok(())
    }

    /// todo 6: the ledger keeps the last 20 runs of a schedule.
    #[test]
    fn the_ledger_keeps_twenty_runs() -> TestResult {
        let (_directory, state) = state()?;
        let ledger = RunLedger::new(state);
        for slot in 1..=25_i64 {
            let _: i64 = ledger.begin("aa", Trigger::Slot(slot), slot)?;
        }
        let runs = ledger.runs("aa")?;
        assert_eq!(runs.len(), 20, "kept");
        assert_eq!(
            runs.first().and_then(|run| run.slot),
            Some(6),
            "oldest dropped"
        );
        ledger.forget("aa")?;
        assert_eq!(ledger.runs("aa")?, [], "forgotten");
        Ok(())
    }

    /// todo 6: removing a router pauses only that router's schedules.
    #[test]
    fn pause_router_pauses_only_that_routers_schedules() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state);
        let home = create(&store, "a", "home", Action::Backup)?;
        let lab = create(&store, "a", "lab", Action::Backup)?;
        assert_eq!(
            store.pause_router("home", NOW + 5)?,
            slice::from_ref(&home.id)
        );
        assert_eq!(
            store.get(&admin(), &home.id)?.state,
            ScheduleState::Paused {
                reason: PauseReason::RouterRemoved,
                at: NOW + 5
            }
        );
        assert_eq!(store.get(&admin(), &lab.id)?.state, ScheduleState::Active);
        let paused = store.pause_for(&lab.id, PauseReason::OwnerUnavailable, NOW + 6)?;
        assert_eq!(
            paused.state,
            ScheduleState::Paused {
                reason: PauseReason::OwnerUnavailable,
                at: NOW + 6
            }
        );
        Ok(())
    }

    /// todo 6: the unsaved note names the latest successful unsaved policy or preset run.
    #[test]
    fn last_unsaved_names_the_latest_unsaved_change_run() -> TestResult {
        let (_directory, state) = state()?;
        let store = ScheduleStore::new(state.clone());
        let ledger = RunLedger::new(state);
        let policy = create(&store, "policy", "home", policy_switch()?)?;
        let backup = create(&store, "backup", "home", Action::Backup)?;
        assert_eq!(ledger.last_unsaved("home")?, None, "no run yet");
        let started = ledger.begin(&policy.id, Trigger::Slot(NOW + 60), NOW + 60)?;
        let succeeded = || RunOutcome::Succeeded {
            unsaved: true,
            checksum: Some("c1".to_owned()),
        };
        ledger.finish(&policy.id, started, succeeded(), None, NOW + 70)?;
        let later = ledger.begin(&backup.id, Trigger::Slot(NOW + 80), NOW + 80)?;
        ledger.finish(&backup.id, later, succeeded(), None, NOW + 90)?;
        let unsaved = ledger.last_unsaved("home")?.ok_or("no unsaved run")?;
        assert_eq!(
            (
                unsaved.schedule_id.as_str(),
                unsaved.name.as_str(),
                unsaved.finished_at,
                unsaved.checksum.as_deref()
            ),
            (policy.id.as_str(), "policy", NOW + 70, Some("c1"))
        );
        assert_eq!(ledger.last_unsaved("lab")?, None, "other router");
        Ok(())
    }
}
