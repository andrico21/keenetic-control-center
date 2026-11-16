//! The confirmation a submission asks for follows the planned change's risk, and the
//! recovery timer follows a management operation whatever risk its siblings raise the
//! change to.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use core::error::Error;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::{IntoResponse as _, Response},
        routing::post,
    };
    use kcc_catalog::Risk;
    use kcc_domain::{ChangeOp, DomainError, RouterCtx, wan};
    use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
    use kcc_rci::ObjectName;
    use tower::ServiceExt as _;

    use super::super::{
        Form, Invalid, Planned, Submission,
        submit_tests::tests::{MTU, ROUTER, World, again, body, checked, params},
    };
    use crate::{
        WebState,
        authz::CurrentUser,
        brackets::own,
        page_kit::{change::Change, request::Params},
    };

    /// A form whose answers say nothing of their own.
    struct Plain;

    impl Form for Plain {
        fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
    }

    /// The MTU write of `ISP`, planned once for each of `risks`.
    fn mtu_at(domain: &RouterCtx, risks: &[Risk]) -> Result<Planned, DomainError> {
        let name = ObjectName::try_from("ISP".to_owned())
            .map_err(|_error| DomainError::InvalidResponse)?;
        let planned = wan::plan_mtu(domain, &name, 1400)?;
        let request = wan::change_request(&name, &planned)?;
        let operations: Vec<ChangeOp> = risks
            .iter()
            .map(|risk| {
                let mut operation = planned.clone();
                operation.risk = *risk;
                operation
            })
            .collect();
        Ok(Planned::of(&operations, Change::Cli(request)))
    }

    /// The commands the fake router received.
    fn commands(world: &World) -> Vec<String> {
        world
            .handle()
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(str::to_owned))
            .collect()
    }

    /// W2-01, W3-01: a planned management or destructive change asks first, although the
    /// page asked for no confirmation, and nothing reaches the router before it.
    #[tokio::test]
    async fn a_planned_risk_asks_for_its_dialog_before_anything_is_sent()
    -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let cases: [(Risk, MessageKey); 2] = [
            (Risk::Management, keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT),
            (Risk::Destructive, keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TEXT),
        ];
        for (risk, text) in cases {
            let opened = MTU.open(world.web(), world.admin(), ROUTER).await.ok();
            let action = opened.ok_or("the write opens")?;
            let typed = params("1400");
            let answer = Submission::new(action, &typed, Plain, again())
                .submit(
                    checked,
                    async |_mtu, domain| mtu_at(domain, &[risk]),
                    async |_domain| None,
                )
                .await;
            let shown = body(answer).await?;
            assert!(
                shown.contains(&format!("data-message-key=\"{}\"", text.id())),
                "{risk:?}: {shown}"
            );
            assert_eq!(
                commands(&world),
                Vec::<String>::new(),
                "{risk:?}: nothing sent"
            );
        }
        Ok(())
    }

    /// The MTU write planned as a management and a destructive operation, confirmed with
    /// the router's name, submitted by `admin`.
    // NOT cancel-safe: see `Action::run_planned`.
    async fn mixed(web: WebState, admin: CurrentUser) -> Response {
        let opened = MTU.open(&web, &admin, ROUTER).await.ok();
        let Some(action) = opened else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let typed = Params::of(vec![
            ("name".to_owned(), "ISP".to_owned()),
            ("value".to_owned(), "1400".to_owned()),
            ("confirm".to_owned(), "yes".to_owned()),
            ("confirm_name".to_owned(), ROUTER.to_owned()),
        ]);
        Submission::new(action, &typed, Plain, again())
            .submit(
                checked,
                async |_mtu, domain| mtu_at(domain, &[Risk::Management, Risk::Destructive]),
                async |_domain| None,
            )
            .await
    }

    /// W2-05: a destructive change that also changes how kcc reaches the router still
    /// runs inside the recovery timer.
    #[tokio::test]
    async fn a_destructive_change_with_a_management_operation_keeps_the_timer()
    -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let web = world.web().clone();
        let admin: CurrentUser = world.admin().clone();
        let app = Router::new()
            .route("/", post(move || mixed(web.clone(), admin.clone())))
            .layer(middleware::from_fn(own));
        let answer = app.oneshot(Request::post("/").body(Body::empty())?).await?;
        assert_eq!(answer.status(), StatusCode::OK, "ran");
        let sent = commands(&world);
        assert_eq!(
            sent.first().map(String::as_str),
            Some("system configuration fail-safe timer reboot 300"),
            "{sent:?}"
        );
        assert_eq!(
            sent.last().map(String::as_str),
            Some("no system configuration fail-safe timer"),
            "{sent:?}"
        );
        Ok(())
    }
}
