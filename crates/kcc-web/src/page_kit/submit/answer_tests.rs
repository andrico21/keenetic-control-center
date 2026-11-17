//! How the page's form answers a submission beyond its check.
//!
//! A refused plan in words of the domain's error, a change that ran recast by the form
//! and landed where the submission says, and values checked for a page that makes no
//! change of its own.
//!
//! A change that runs needs the request owner of the Web UI's middleware, so the change
//! that "ran" here is one the operator may not take: the run refuses it as `forbidden`.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use core::{error::Error, future::ready};

    use axum::{
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use kcc_app::workflow::WorkflowError;
    use kcc_catalog::Risk;
    use kcc_domain::DomainError;
    use kcc_i18n::locale::Locale;

    use super::super::{
        Form, Invalid, Planned, Submission,
        submit_tests::tests::{
            FORM_STATUS, MTU, ROUTER, World, again, body, checked, outcomes, params,
        },
        unplanned::Unplanned,
    };
    use crate::{
        markup::Rendered,
        page_kit::outcome::{Failure, Outcome},
    };

    /// What the test form answers a change that ran with.
    const RAN: StatusCode = StatusCode::ACCEPTED;

    /// A form that answers each end itself: a change that ran with its audited outcome.
    struct Recasting;

    impl Form for Recasting {
        fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
            FORM_STATUS.into_response()
        }

        fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
            (FORM_STATUS, failure.audit()).into_response()
        }

        fn answer_unplanned(
            self,
            unplanned: Unplanned<'_>,
            _locale: Locale,
        ) -> impl Future<Output = Response> {
            let protected = matches!(unplanned.error(), DomainError::ProtectedAccount);
            ready((FORM_STATUS, if protected { "protected" } else { "refused" }).into_response())
        }

        fn answer_changed(
            self,
            outcome: Outcome,
            _refreshed: Option<Rendered>,
            _locale: Locale,
        ) -> Response {
            (RAN, outcome.audit()).into_response()
        }
    }

    /// Work at the destructive risk, which an operator may not take: it never starts.
    fn destructive() -> Planned {
        Planned::assessed(Risk::Destructive, |_changes, _context| {
            Box::pin(async { Err(WorkflowError::InvalidResponse) })
        })
    }

    /// The `hx-retarget` header of `answer`.
    fn retarget(answer: &Response) -> Option<&str> {
        answer
            .headers()
            .get("hx-retarget")
            .and_then(|value| value.to_str().ok())
    }

    #[tokio::test]
    async fn a_refused_plan_is_answered_in_words_of_the_domains_error() -> Result<(), Box<dyn Error>>
    {
        let world = World::new().await?;
        let opened = MTU.open(world.web(), world.admin(), ROUTER).await.ok();
        let action = opened.ok_or("the write opens")?;
        let typed = params("1400");
        let answer = Submission::new(action, &typed, Recasting, again())
            .submit(
                checked,
                async |_mtu, _domain| Err(DomainError::ProtectedAccount),
                async |_domain| None,
            )
            .await;
        assert_eq!(answer.status(), FORM_STATUS, "the form answers");
        assert_eq!(body(answer).await?, "protected", "with the domain's error");
        assert_eq!(outcomes(&world.state_dir())?, ["failed"]);
        Ok(())
    }

    #[tokio::test]
    async fn the_form_recasts_the_answer_to_a_change_that_ran() -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let opened = MTU.open(world.web(), world.operator(), ROUTER).await.ok();
        let action = opened.ok_or("the write opens")?;
        let before = world.handle().request_count();
        let typed = params("1400");
        let answer = Submission::new(action, &typed, Recasting, again())
            .submit(
                checked,
                async |_mtu, _domain| Ok(destructive()),
                async |_domain| None,
            )
            .await;
        assert_eq!(answer.status(), RAN, "the form answers the run");
        assert_eq!(body(answer).await?, "forbidden", "with the run's outcome");
        assert_eq!(world.handle().request_count(), before, "nothing sent");
        assert_eq!(outcomes(&world.state_dir())?, ["forbidden"]);
        Ok(())
    }

    #[tokio::test]
    async fn only_the_answer_to_a_change_that_ran_lands_in_the_run_landing()
    -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let typed = params("1400");
        let mut landed = Vec::new();
        for planned in [None, Some(destructive)] {
            let opened = MTU.open(world.web(), world.operator(), ROUTER).await.ok();
            let action = opened.ok_or("the write opens")?;
            let answer = Submission::new(action, &typed, Recasting, again())
                .landing_run_in("#page-outcome")
                .submit(
                    checked,
                    async move |_mtu, _domain| {
                        planned
                            .map(|plan| plan())
                            .ok_or(DomainError::InvalidResponse)
                    },
                    async |_domain| None,
                )
                .await;
            landed.push(retarget(&answer).map(str::to_owned));
        }
        assert_eq!(
            landed,
            [None, Some("#page-outcome".to_owned())],
            "a refusal stays, the run's answer lands"
        );
        Ok(())
    }

    #[tokio::test]
    async fn values_checked_for_a_page_that_makes_no_change() -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let mut statuses = Vec::new();
        for typed in [params("big"), params("1400")] {
            let opened = MTU.open(world.web(), world.admin(), ROUTER).await.ok();
            let action = opened.ok_or("the write opens")?;
            let before = world.handle().request_count();
            let checking = Submission::new(action, &typed, Recasting, again()).checked(checked);
            statuses.push(match checking.await {
                Ok((_action, mtu)) => Ok(mtu),
                Err(answer) => Err(answer.into_response().status()),
            });
            assert_eq!(world.handle().request_count(), before, "nothing sent");
        }
        assert_eq!(statuses, [Err(FORM_STATUS), Ok(1400)]);
        assert_eq!(outcomes(&world.state_dir())?, ["validation_failed"]);
        Ok(())
    }
}
