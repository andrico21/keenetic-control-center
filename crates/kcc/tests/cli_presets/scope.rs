//! `kcc preset` router scope: a scoped capture never replaces a preset of another router,
//! and a preset of another router answers like a missing one.

use std::fs;

use kcc_app::audit::read_entries;
use kcc_testkit::model::Profile;

use super::{fixture::Pair, support::TestResult};

/// Runs `kcc preset capture --from <from> --groups dns-secure --name <name>`.
fn capture(pair: &Pair, from: &str, name: &str) -> TestResult<i32> {
    let run = pair.env.kcc(&[
        "preset",
        "capture",
        "--from",
        from,
        "--groups",
        "dns-secure",
        "--name",
        name,
    ])?;
    Ok(run.code)
}

/// E-02, G-02: a scoped capture never replaces a preset of another router.
///
/// A principal scoped to `fake-a` captures, from its router and from a file, under the id
/// of a preset sourced from `fake-b`: both captures exit 10, are audited as refused, and
/// the stored record stays byte for byte. Its own preset is recaptured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scoped_capture_cannot_replace_a_preset_of_another_router() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    assert_eq!(capture(&pair, "fake-b", "office")?, 0_i32);
    let path = pair.env.state_dir().join("presets/office.json");
    let before = fs::read(&path)?;
    let file = pair.env.write(
        "source.txt",
        "! $$$ Version: 5.1.0\ndns-proxy tls upstream 1.1.1.1 853\n",
    )?;
    pair.with_cli("role = \"operator\"\nrouter_scope = [\"fake-a\"]")?;

    let from_file = format!("file:{}", file.display());
    for from in ["fake-a", from_file.as_str()] {
        assert_eq!(capture(&pair, from, "office")?, 10_i32, "{from}");
    }

    assert_eq!(fs::read(&path)?, before);
    let refused = read_entries(&pair.env.state_dir())?
        .into_iter()
        .filter(|entry| entry.action == "cli.preset.capture" && entry.outcome == "forbidden")
        .count();
    assert_eq!(refused, 2);
    for _ in 0..2_u8 {
        assert_eq!(capture(&pair, "fake-a", "bench")?, 0_i32);
    }
    pair.stop().await
}

/// E-02, G-02: a preset of another router answers like a missing one.
///
/// `show`, `delete` and `plan` of a preset sourced from `fake-b` answer a principal scoped
/// to `fake-a` exactly what a missing id answers, and nothing is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preset_of_another_router_answers_like_a_missing_one() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    assert_eq!(capture(&pair, "fake-b", "office")?, 0_i32);
    let path = pair.env.state_dir().join("presets/office.json");
    let before = fs::read(&path)?;
    pair.with_cli("role = \"operator\"\nrouter_scope = [\"fake-a\"]")?;

    for command in [
        &["--json", "preset", "show"][..],
        &["--json", "preset", "delete"],
        &["--router", "fake-a", "--json", "preset", "plan"],
    ] {
        let mut answers = Vec::new();
        for id in ["office", "absent"] {
            let mut args = command.to_vec();
            args.push(id);
            let run = pair.env.kcc(&args)?;
            answers.push((
                run.code,
                run.stdout.replace(id, "<id>"),
                run.stderr.replace(id, "<id>"),
            ));
        }
        assert_eq!(answers.first(), answers.get(1), "{command:?}");
    }
    assert_eq!(fs::read(&path)?, before);
    pair.stop().await
}
