//! Todo 31 pages and floods: the browser pages refuse framing and referrers, and a flood of
//! authorization requests from many addresses keeps a legitimate pending request.

#[cfg(test)]
mod tests {
    use reqwest::{Response, StatusCode};

    use crate::{
        browser::{self, Browser},
        fixture::{Fixture, Options, PASSWORD, TestResult},
        flow::{begin, client},
    };

    /// Asserts that `response` (named `page`) may not be framed and sends no referrer.
    fn unframed(response: &Response, page: &str) {
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(header("x-frame-options").as_deref(), Some("deny"), "{page}");
        assert_eq!(
            header("referrer-policy").as_deref(),
            Some("no-referrer"),
            "{page}"
        );
        assert!(
            header("content-security-policy")
                .unwrap_or_default()
                .contains("frame-ancestors 'none'"),
            "{page}"
        );
    }

    /// Todo 31 (C13b, C14): the login-resume page, the consent page and the error page
    /// carry `X-Frame-Options: deny`, `Referrer-Policy: no-referrer` and a policy with
    /// `frame-ancestors 'none'`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_browser_pages_refuse_framing_and_referrers() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let consent = begin(&fixture, &server, &first).await?;
        let page = format!("/ui/oauth/consent?request={}", consent.id);
        let login = fixture
            .http()
            .get(format!("{}{page}", server.base()))
            .send()
            .await?;
        assert_eq!(login.status(), StatusCode::OK);
        unframed(&login, "login resume");
        assert!(browser::resume_field(&login.text().await?).is_some());
        let browser = Browser::resume(&fixture, &server, ("alice", PASSWORD), &consent.id).await?;
        let shown = browser.get(&fixture, &page).await?;
        assert_eq!(shown.status(), StatusCode::OK);
        unframed(&shown, "consent");
        let error = fixture
            .http()
            .get(format!(
                "{}/oauth/authorize?response_type=code&client_id=ffff",
                server.base()
            ))
            .send()
            .await?;
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        unframed(&error, "error");
        Ok(())
    }

    /// Todo 31 (N5): a request opened first is still approvable after 1000 loopback
    /// addresses sent 5 authorization requests each and one address sent 5000.
    ///
    /// Linux only: other systems route only `127.0.0.1` on the loopback interface.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flood_from_many_addresses_keeps_a_pending_request() -> TestResult {
        use core::net::{IpAddr, Ipv4Addr};

        use reqwest::{Client, redirect::Policy};

        use crate::{
            fixture::LIMIT,
            flow::{self, Pkce, REDIRECT},
        };

        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let legit = begin(&fixture, &server, &first).await?;
        let pkce = Pkce::new()?;
        let url = format!(
            "{}/oauth/authorize?response_type=code&client_id={first}&redirect_uri={REDIRECT}\
             &code_challenge={}&code_challenge_method=S256&resource={}",
            server.base(),
            pkce.challenge,
            server.resource(),
        );
        let from = |host: u16| -> TestResult<Client> {
            let [high, low] = host.to_be_bytes();
            Ok(Client::builder()
                .local_address(IpAddr::V4(Ipv4Addr::new(127, 3, high, low)))
                .redirect(Policy::none())
                .timeout(LIMIT)
                .build()?)
        };
        for host in 1_u16..=1000 {
            let sender = from(host)?;
            for _request in 0_u8..5 {
                let status = sender.get(&url).send().await?.status();
                assert_eq!(status, StatusCode::SEE_OTHER, "address {host}");
            }
        }
        let one = from(2000)?;
        for _request in 0_u16..5000 {
            let status = one.get(&url).send().await?.status();
            assert!(
                status == StatusCode::SEE_OTHER || status == StatusCode::TOO_MANY_REQUESTS,
                "{status}"
            );
        }
        let code = flow::approve(&fixture, &server, &legit, "alice").await?;
        assert!(!code.is_empty(), "the first request is approved");
        Ok(())
    }
}
