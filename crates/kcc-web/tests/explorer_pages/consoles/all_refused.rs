//! A batch whose every item the router refused shows those refusals, not an answer.
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{BatchKind, batch_outcome};
use crate::{html, support::TestResult};

/// Every item refused: the reply lists each item's refusal in the router's words and
/// shows no answer viewer, which held only `[ null, null ]` (F3 O-7).
#[tokio::test]
async fn wholly_refused_batches_show_each_refusal_and_no_empty_answer() -> TestResult {
    let (body, audited) =
        batch_outcome(&[BatchKind::Description, BatchKind::Country], "/system").await?;
    assert_eq!(audited, "failed", "audited as before");
    for index in ["1", "2"] {
        let mut args = FluentArgs::new();
        args.set("index", index);
        args.set("issue", "injected batch refusal.");
        let refusal = html(&tr(Locale::En, keys::WEB_EXPLORER_ISSUE_ITEM, Some(&args)));
        assert!(body.contains(&refusal), "item {index}: {body}");
    }
    assert!(
        !body.contains("class=\"viewer\""),
        "no viewer of empty answers: {body}"
    );
    Ok(())
}
