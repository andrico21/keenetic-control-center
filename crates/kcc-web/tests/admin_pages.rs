//! Administration pages: users and roles, their privilege guards, the forced password
//! change at the first sign-in, API keys with the MCP hot reload, the audit log and the
//! server summary.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{fs, path::PathBuf};

    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use futures_util::StreamExt as _;
    use kcc_app::{
        accounts::{AccountStore, NewAccount},
        api_keys::api_key_entries,
        audit::{Actor, ActorKind, AuditEvent, AuditLog},
        permissions::{Permission, Role, RolesDocument, load_roles},
        persist::StateStore,
        settings::Config,
    };
    use kcc_i18n::{
        bundle::{MessageKey, tr},
        keys,
        locale::Locale,
    };
    use kcc_web::{
        admin::{AdminServices, AuthReload, ReloadError, ServerFacts, TransportReload},
        session::CookieSecurity,
        web_router,
    };
    use rmcp::ServerHandler;
    use rmcp_server_kit::{
        auth::AuthConfig,
        transport::{McpServerConfig, serve_with_listener},
    };
    use secrecy::SecretString;
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use tower::ServiceExt as _;
    use url::form_urlencoded;

    use crate::support::{
        base::{Core, Frozen, ORIGIN, PASSWORD},
        outcome::TestResult,
        page::{cookie_pair, en, en_with, header_text, meta_content, text},
    };

    const ADMIN: &str = "alice";

    /// Counts the reloads the pages ask for.
    #[derive(Debug, Default)]
    struct CountingReload {
        keys: AtomicUsize,
        rbac: AtomicUsize,
    }

    impl AuthReload for CountingReload {
        fn reload_keys(&self) -> Result<(), ReloadError> {
            let _: usize = self.keys.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn reload_rbac(&self) -> Result<(), ReloadError> {
            let _: usize = self.rbac.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A reload that breaks `api_keys.json` when the keys are installed, so the next read
    /// of the keys fails.
    #[derive(Debug)]
    struct BreakingReload {
        keys_file: PathBuf,
    }

    impl AuthReload for BreakingReload {
        fn reload_keys(&self) -> Result<(), ReloadError> {
            fs::write(&self.keys_file, "{").map_err(|_error| ReloadError::NotReady)
        }

        fn reload_rbac(&self) -> Result<(), ReloadError> {
            Ok(())
        }
    }

    /// A signed-in browser: its session cookie and CSRF token.
    struct Browser {
        cookie: String,
        csrf: String,
    }

    /// A fixture and, when requested, its transport reload bridge.
    type Built = (Fixture, Option<Arc<TransportReload>>);

    struct Fixture {
        _directory: TempDir,
        state: StateStore,
        accounts: Arc<AccountStore>,
        audit: AuditLog,
        reload: Arc<CountingReload>,
        router: Router,
    }

    /// How [`Fixture::build`] wires the admin services.
    #[derive(Default)]
    struct Options {
        /// Reload through a [`TransportReload`] bridge.
        transport: bool,
        /// Reload through a [`BreakingReload`] (when `transport` is off).
        breaking: bool,
        /// The configuration the server page reports.
        config: Config,
    }

    impl Fixture {
        /// The admin `alice` (in `locale`), the custom `roles` and the attached admin
        /// pages, reporting reloads to [`Fixture::reload`].
        fn new(locale: &str, roles: Vec<Role>) -> Result<Self, Box<dyn Error + Send + Sync>> {
            Ok(Self::build(locale, roles, &Options::default())?.0)
        }

        /// As [`Fixture::new`]; with `options.transport`, reloads go through a
        /// [`TransportReload`] bridge (returned) instead of the counter, and the server
        /// page reports `options.config`.
        fn build(
            locale: &str,
            roles: Vec<Role>,
            options: &Options,
        ) -> Result<Built, Box<dyn Error + Send + Sync>> {
            let core = Core::new(
                Arc::new(Frozen::at(0)),
                &[(ADMIN, "admin", Some(locale))],
                &[],
            )?;
            if !roles.is_empty() {
                core.state
                    .update(|document: &mut RolesDocument| document.roles.extend(roles))?;
            }
            let reload = Arc::new(CountingReload::default());
            let transport_reload = options
                .transport
                .then(|| Arc::new(TransportReload::new(core.state.clone(), Vec::new())));
            let bridge: Arc<dyn AuthReload> = match &transport_reload {
                Some(kit) => Arc::<TransportReload>::clone(kit),
                None if options.breaking => Arc::new(BreakingReload {
                    keys_file: core.state.dir().join("api_keys.json"),
                }),
                None => Arc::<CountingReload>::clone(&reload),
            };
            let web_state = core
                .web(
                    load_roles(&core.state)?,
                    (Duration::from_mins(30), Duration::from_hours(12)),
                    CookieSecurity::LoopbackHttp,
                )
                .with_admin(AdminServices {
                    state: core.state.clone(),
                    reload: Some(bridge),
                    server: ServerFacts::from_config("9.9.9".to_owned(), &options.config),
                });
            let fixture = Self {
                _directory: core.directory,
                state: core.state,
                accounts: core.accounts,
                audit: core.audit,
                reload,
                router: web_router(web_state),
            };
            Ok((fixture, transport_reload))
        }

        /// Adds an account that does not have to change its password.
        fn add_user(&self, name: &str, role: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.accounts.create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                NewAccount::new(
                    name.to_owned(),
                    SecretString::from(PASSWORD),
                    role.to_owned(),
                ),
            )?;
            Ok(())
        }

        async fn send(
            &self,
            request: Request<Body>,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            Ok(self.router.clone().oneshot(request).await?)
        }

        async fn get(
            &self,
            path: &str,
            cookie: &str,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            self.send(
                Request::get(path)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
            )
            .await
        }

        async fn post(
            &self,
            browser: &Browser,
            path: &str,
            pairs: &[(&str, &str)],
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            let body = {
                let mut serializer = form_urlencoded::Serializer::new(String::new());
                for (name, value) in pairs {
                    let _: &mut form_urlencoded::Serializer<'_, String> =
                        serializer.append_pair(name, value);
                }
                serializer.finish()
            };
            self.send(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::COOKIE, &browser.cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", &browser.csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))?,
            )
            .await
        }

        /// Signs `name` in with `password`; the CSRF token comes from `page`.
        async fn sign_in(
            &self,
            name: &str,
            password: &str,
            page: &str,
        ) -> Result<(Browser, Option<String>), Box<dyn Error + Send + Sync>> {
            let login = self.get("/ui/login", "").await?;
            let anonymous_cookie = cookie_pair(&login)?;
            let login_html = text(login).await?;
            let anonymous = Browser {
                cookie: anonymous_cookie,
                csrf: meta_content(&login_html, "csrf-token").ok_or("login CSRF")?,
            };
            let response = self
                .post(
                    &anonymous,
                    "/ui/login",
                    &[("username", name), ("password", password)],
                )
                .await?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{name} signs in");
            let location = header_text(&response, header::LOCATION.as_str());
            let cookie = cookie_pair(&response)?;
            let landing = self.get(page, &cookie).await?;
            let html = text(landing).await?;
            let csrf = meta_content(&html, "csrf-token").ok_or("page CSRF")?;
            Ok((Browser { cookie, csrf }, location))
        }

        async fn admin(&self) -> Result<Browser, Box<dyn Error + Send + Sync>> {
            Ok(self.sign_in(ADMIN, PASSWORD, "/ui/admin/users").await?.0)
        }

        fn audit_log(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            Ok(fs::read_to_string(self.state.dir().join("audit.jsonl"))?)
        }
    }

    /// `key` in Ukrainian.
    fn uk(key: MessageKey) -> String {
        tr(Locale::Uk, key, None)
    }

    fn role(name: &str, permissions: &[Permission], scope: &[&str]) -> Role {
        Role::new(
            name.to_owned(),
            permissions.iter().copied(),
            scope.iter().map(|glob| (*glob).to_owned()).collect(),
        )
    }

    #[tokio::test]
    async fn the_users_page_renders_for_each_role() -> TestResult {
        let user_admin = role(
            "useradmin",
            &[Permission::Read, Permission::ManageUsers],
            &["*"],
        );
        let fixture = Fixture::new("en", vec![user_admin])?;
        fixture.add_user("vera", "viewer")?;
        fixture.add_user("una", "useradmin")?;
        let admin = fixture.admin().await?;

        let page = fixture.get("/ui/admin/users", &admin.cookie).await?;
        assert_eq!(page.status(), StatusCode::OK, "admin page");
        let admin_html = text(page).await?;
        for expected in [
            "hx-get=\"/ui/admin/users/new\"",
            "href=\"/ui/admin/audit\"",
            "alice <span class=\"muted\">(you)</span>",
            "/ui/admin/users/role?name=vera",
            "/ui/admin/users/delete?name=una",
        ] {
            assert!(admin_html.contains(expected), "missing {expected}");
        }
        assert!(
            !admin_html.contains("/ui/admin/users/delete?name=alice"),
            "no actions on the own account"
        );

        let (viewer, _) = fixture.sign_in("vera", PASSWORD, "/ui/").await?;
        let refused = fixture.get("/ui/admin/users", &viewer.cookie).await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "viewer");
        assert!(
            text(refused)
                .await?
                .contains(&en(keys::WEB_ERROR_FORBIDDEN_TITLE)),
            "403 page"
        );
        let viewer_landing = fixture.get("/ui/admin", &viewer.cookie).await?;
        assert_eq!(
            viewer_landing.status(),
            StatusCode::FORBIDDEN,
            "viewer landing"
        );

        let (manager, _) = fixture.sign_in("una", PASSWORD, "/ui/").await?;
        let manager_html = text(fixture.get("/ui/admin/users", &manager.cookie).await?).await?;
        assert!(
            manager_html.contains("/ui/admin/users/role?name=vera"),
            "a viewer is below useradmin"
        );
        assert!(
            !manager_html.contains("/ui/admin/users/role?name=alice"),
            "an admin is above useradmin"
        );
        assert!(
            !manager_html.contains("href=\"/ui/admin/audit\""),
            "no audit tab without ViewAudit"
        );
        let manager_landing = fixture.get("/ui/admin", &manager.cookie).await?;
        assert_eq!(
            header_text(&manager_landing, header::LOCATION.as_str()).as_deref(),
            Some("/ui/admin/users"),
            "landing opens the users page"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_created_user_must_change_the_initial_password_first() -> TestResult {
        let fixture = Fixture::new("en", Vec::new())?;
        let admin = fixture.admin().await?;
        let initial = "initial passphrase 42";

        let created = fixture
            .post(
                &admin,
                "/ui/admin/users",
                &[
                    ("username", "bob"),
                    ("password", initial),
                    ("role", "operator"),
                    ("locale", "de"),
                ],
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "created");
        assert_eq!(
            header_text(&created, "hx-trigger-after-swap").as_deref(),
            Some("kcc:dialog-close"),
            "the dialog closes"
        );
        let html = text(created).await?;
        assert!(html.contains(&en(keys::WEB_ADMIN_USER_CREATED)), "toast");
        assert!(
            html.contains(&en(keys::WEB_ADMIN_USER_MUST_CHANGE)),
            "flag in the table"
        );
        assert!(!html.contains(initial), "the password is never echoed");
        let log = fixture.audit_log()?;
        assert!(log.contains("\"admin.user_create\""), "audited");
        assert!(!log.contains(initial), "no password in the audit log");

        let (bob, landing) = fixture.sign_in("bob", initial, "/ui/account").await?;
        assert_eq!(landing.as_deref(), Some("/ui/account"), "first stop");
        let blocked = fixture.get("/ui/", &bob.cookie).await?;
        assert_eq!(
            header_text(&blocked, header::LOCATION.as_str()).as_deref(),
            Some("/ui/account"),
            "every other page waits for the new password"
        );
        let account = text(fixture.get("/ui/account", &bob.cookie).await?).await?;
        assert!(
            account.contains(&tr(Locale::De, keys::WEB_ADMIN_PASSWORD_REQUIRED, None)),
            "the notice speaks the account language"
        );

        let changed = fixture
            .post(
                &bob,
                "/ui/account/password",
                &[
                    ("current_password", initial),
                    ("new_password", "my own passphrase 7"),
                ],
            )
            .await?;
        assert_eq!(
            header_text(&changed, "hx-redirect").as_deref(),
            Some("/ui/"),
            "into the dashboard"
        );
        let rotated = cookie_pair(&changed)?;
        assert_ne!(rotated, bob.cookie, "the session id rotates");
        let old = fixture.get("/ui/", &bob.cookie).await?;
        assert_eq!(
            header_text(&old, header::LOCATION.as_str()).as_deref(),
            Some("/ui/login"),
            "the restricted session ended"
        );
        let open = fixture.get("/ui/", &rotated).await?;
        assert_eq!(open.status(), StatusCode::OK, "full access");
        Ok(())
    }

    #[tokio::test]
    async fn invalid_users_and_roles_get_localized_field_errors() -> TestResult {
        let fixture = Fixture::new("uk", Vec::new())?;
        let admin = fixture.admin().await?;

        let short = fixture
            .post(
                &admin,
                "/ui/admin/users",
                &[
                    ("username", "bob"),
                    ("password", "short"),
                    ("role", "viewer"),
                    ("locale", "en"),
                ],
            )
            .await?;
        assert_eq!(short.status(), StatusCode::UNPROCESSABLE_ENTITY, "short");
        assert!(
            text(short)
                .await?
                .contains(&uk(keys::WEB_ADMIN_ERROR_PASSWORD_LENGTH)),
            "localized password policy"
        );
        let duplicate = fixture
            .post(
                &admin,
                "/ui/admin/users",
                &[
                    ("username", ADMIN),
                    ("password", "long enough passphrase"),
                    ("role", "viewer"),
                    ("locale", "en"),
                ],
            )
            .await?;
        assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY, "dup");
        assert!(
            text(duplicate)
                .await?
                .contains(&uk(keys::WEB_ADMIN_ERROR_USER_EXISTS)),
            "duplicate account"
        );

        for (name, scope, message) in [
            ("admin", "*", keys::WEB_ADMIN_ERROR_ROLE_BUILT_IN),
            ("lab", "lab-[0-9]", keys::WEB_ADMIN_ERROR_SCOPE),
            ("lab", "lab?", keys::WEB_ADMIN_ERROR_SCOPE),
            ("lab", "", keys::WEB_ADMIN_ERROR_SCOPE),
            ("Lab", "lab-*", keys::WEB_ADMIN_ERROR_ROLE_NAME),
        ] {
            let response = fixture
                .post(
                    &admin,
                    "/ui/admin/roles",
                    &[("name", name), ("scope", scope), ("read", "on")],
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{name} {scope}"
            );
            assert!(
                text(response).await?.contains(&uk(message)),
                "{name} {scope}"
            );
        }
        let typed = fixture
            .post(
                &admin,
                "/ui/admin/roles",
                &[("name", "Lab"), ("scope", "lab-*"), ("write", "on")],
            )
            .await?;
        let form = text(typed).await?;
        for kept in [
            "name=\"name\" type=\"text\" value=\"Lab\"",
            "name=\"scope\" type=\"text\" value=\"lab-*\"",
            "name=\"write\" value=\"on\" checked",
        ] {
            assert!(form.contains(kept), "the form keeps {kept}");
        }
        assert_eq!(fixture.reload.rbac.load(Ordering::SeqCst), 0, "no reload");
        Ok(())
    }

    #[tokio::test]
    async fn nobody_acts_on_their_own_account_or_above_their_role() -> TestResult {
        let user_admin = role(
            "useradmin",
            &[Permission::Read, Permission::ManageUsers],
            &["*"],
        );
        let fixture = Fixture::new("en", vec![user_admin])?;
        fixture.add_user("una", "useradmin")?;
        let admin = fixture.admin().await?;

        for (path, pairs) in [
            ("/ui/admin/users/disable", vec![("name", ADMIN)]),
            (
                "/ui/admin/users/role",
                vec![("name", ADMIN), ("role", "viewer")],
            ),
            (
                "/ui/admin/users/delete",
                vec![
                    ("object", ADMIN),
                    ("confirm", "yes"),
                    ("confirm_name", ADMIN),
                ],
            ),
        ] {
            let response = fixture.post(&admin, path, &pairs).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "self {path}");
        }

        let (manager, _) = fixture.sign_in("una", PASSWORD, "/ui/").await?;
        let grant = fixture
            .post(
                &manager,
                "/ui/admin/users",
                &[
                    ("username", "eve"),
                    ("password", "long enough passphrase"),
                    ("role", "operator"),
                    ("locale", "en"),
                ],
            )
            .await?;
        assert_eq!(grant.status(), StatusCode::FORBIDDEN, "operator is above");
        let raw = fixture
            .post(
                &manager,
                "/ui/admin/roles",
                &[("name", "rawer"), ("scope", "*"), ("raw_rci", "on")],
            )
            .await?;
        assert_eq!(raw.status(), StatusCode::FORBIDDEN, "RawRci is not held");
        let above = fixture
            .post(&manager, "/ui/admin/users/disable", &[("name", ADMIN)])
            .await?;
        assert_eq!(above.status(), StatusCode::FORBIDDEN, "admin is above");
        let own_role = fixture
            .post(
                &manager,
                "/ui/admin/roles/edit",
                &[("name", "useradmin"), ("scope", "*"), ("read", "on")],
            )
            .await?;
        assert_eq!(own_role.status(), StatusCode::FORBIDDEN, "own role");
        assert!(
            fixture.audit_log()?.contains("\"forbidden\""),
            "refusals are audited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_last_enabled_admin_stays() -> TestResult {
        let root = role("root", &Permission::ALL, &["*"]);
        let fixture = Fixture::new("en", vec![root])?;
        fixture.add_user("carol", "root")?;
        let (carol, _) = fixture.sign_in("carol", PASSWORD, "/ui/").await?;

        let disable = fixture
            .post(&carol, "/ui/admin/users/disable", &[("name", ADMIN)])
            .await?;
        assert_eq!(
            disable.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "disable"
        );
        assert!(
            text(disable)
                .await?
                .contains(&en(keys::WEB_ADMIN_ERROR_LAST_ADMIN)),
            "localized refusal toast"
        );
        let demote = fixture
            .post(
                &carol,
                "/ui/admin/users/role",
                &[("name", ADMIN), ("role", "viewer")],
            )
            .await?;
        assert_eq!(demote.status(), StatusCode::UNPROCESSABLE_ENTITY, "demote");
        let delete = fixture
            .post(
                &carol,
                "/ui/admin/users/delete",
                &[
                    ("object", ADMIN),
                    ("confirm", "yes"),
                    ("confirm_name", ADMIN),
                ],
            )
            .await?;
        assert_eq!(delete.status(), StatusCode::UNPROCESSABLE_ENTITY, "delete");
        assert!(fixture.accounts.has_admin()?, "alice is still the admin");

        let mistyped = fixture
            .post(
                &carol,
                "/ui/admin/users/delete",
                &[
                    ("object", ADMIN),
                    ("confirm", "yes"),
                    ("confirm_name", "alicia"),
                ],
            )
            .await?;
        assert_eq!(mistyped.status(), StatusCode::UNPROCESSABLE_ENTITY, "typo");
        assert!(
            text(mistyped)
                .await?
                .contains(&en(keys::WEB_ADMIN_ERROR_CONFIRM)),
            "typed confirmation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn custom_roles_reach_rbac_and_cannot_be_deleted_while_held() -> TestResult {
        let fixture = Fixture::new("en", Vec::new())?;
        let admin = fixture.admin().await?;

        let created = fixture
            .post(
                &admin,
                "/ui/admin/roles",
                &[
                    ("name", "lab-ops"),
                    ("scope", "lab-*, branch-1"),
                    ("read", "on"),
                    ("write", "on"),
                ],
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "created");
        assert!(
            text(created)
                .await?
                .contains(&en(keys::WEB_ADMIN_ROLE_CREATED)),
            "toast"
        );
        assert_eq!(fixture.reload.rbac.load(Ordering::SeqCst), 1, "RBAC reload");
        let stored = load_roles(&fixture.state)?;
        let lab = stored
            .iter()
            .find(|candidate| candidate.name == "lab-ops")
            .ok_or("lab-ops persisted")?;
        assert_eq!(lab.router_scope, ["lab-*", "branch-1"], "globs in order");
        assert!(
            lab.grants(Permission::Write) && !lab.grants(Permission::Save),
            "ticked permissions only"
        );

        let assigned = fixture
            .post(
                &admin,
                "/ui/admin/users",
                &[
                    ("username", "dave"),
                    ("password", "long enough passphrase"),
                    ("role", "lab-ops"),
                    ("locale", "en"),
                ],
            )
            .await?;
        assert_eq!(assigned.status(), StatusCode::OK, "new roles are grantable");
        let (dave, _) = fixture
            .sign_in("dave", "long enough passphrase", "/ui/account")
            .await?;

        let held = fixture
            .post(
                &admin,
                "/ui/admin/roles/delete",
                &[
                    ("object", "lab-ops"),
                    ("confirm", "yes"),
                    ("confirm_name", "lab-ops"),
                ],
            )
            .await?;
        assert_eq!(held.status(), StatusCode::UNPROCESSABLE_ENTITY, "held");
        assert!(
            text(held)
                .await?
                .contains(&en(keys::WEB_ADMIN_ERROR_ROLE_IN_USE)),
            "in-use refusal"
        );

        let edited = fixture
            .post(
                &admin,
                "/ui/admin/roles/edit",
                &[("name", "lab-ops"), ("scope", "lab-*"), ("read", "on")],
            )
            .await?;
        assert_eq!(edited.status(), StatusCode::OK, "edited");
        assert_eq!(fixture.reload.rbac.load(Ordering::SeqCst), 2, "RBAC reload");
        let ended = fixture.get("/ui/account", &dave.cookie).await?;
        assert_eq!(
            header_text(&ended, header::LOCATION.as_str()).as_deref(),
            Some("/ui/login"),
            "sessions holding the edited role end"
        );
        Ok(())
    }

    /// An MCP handler with rmcp's defaults: the key test needs only the transport's
    /// authentication in front of it.
    #[derive(Debug, Clone, Copy)]
    struct Probe;

    impl ServerHandler for Probe {}

    /// The HTTP status of an MCP `initialize` request carrying `key` as bearer token.
    async fn mcp_status(
        address: SocketAddr,
        key: &str,
    ) -> Result<u16, Box<dyn Error + Send + Sync>> {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"admin-pages","version":"1.0.0"}}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut status_line = String::new();
        let _: usize = BufReader::new(stream).read_line(&mut status_line).await?;
        Ok(status_line
            .split_whitespace()
            .nth(1)
            .ok_or("no status code")?
            .parse()?)
    }

    /// The `value` of the input with `id` in `html`.
    fn input_value(html: &str, id: &str) -> Option<String> {
        let marker = format!("id=\"{id}\" type=\"text\" value=\"");
        html.split_once(&marker)
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(value, _)| value.to_owned())
    }

    #[tokio::test]
    async fn a_created_key_authenticates_mcp_until_it_is_revoked() -> TestResult {
        let options = Options {
            transport: true,
            ..Options::default()
        };
        let (fixture, bridge) = Fixture::build("en", Vec::new(), &options)?;
        let slot = bridge.ok_or("transport bridge")?.slot();
        let (installed, handle_ready) = oneshot::channel::<()>();
        let config = McpServerConfig::new("127.0.0.1:0", "kcc-admin-pages", "0.0.0")
            .with_auth(AuthConfig::with_keys(api_key_entries(&fixture.state)?))
            .with_reload_callback(move |handle| {
                let delivered = slot.set(handle).is_ok() && installed.send(()).is_ok();
                assert!(delivered, "one reload handle for one waiting test");
            })
            .validate()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (ready, address_ready) = oneshot::channel();
        let server = tokio::spawn(serve_with_listener(
            listener,
            config,
            || Probe,
            Some(ready),
            None,
        ));
        let address = address_ready.await?;
        handle_ready.await?;
        assert_eq!(
            mcp_status(address, "no-such-key").await?,
            401,
            "unknown key"
        );

        let admin = fixture.admin().await?;
        let created = fixture
            .post(
                &admin,
                "/ui/admin/api-keys",
                &[("name", "probe"), ("role", "viewer")],
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "created");
        assert_eq!(
            header_text(&created, header::CACHE_CONTROL.as_str()).as_deref(),
            Some("no-store, max-age=0"),
            "the response with the key is never stored"
        );
        let html = text(created).await?;
        let key = input_value(&html, "api-key-value").ok_or("key shown once")?;
        assert!(
            !html.contains(&tr(Locale::En, keys::WEB_ADMIN_RELOAD_PENDING, None)),
            "the running transport took the key"
        );
        assert_eq!(
            mcp_status(address, &key).await?,
            200,
            "the key works at once"
        );

        let listing = text(fixture.get("/ui/admin/api-keys", &admin.cookie).await?).await?;
        assert!(listing.contains(">probe</th>"), "listed");
        assert!(!listing.contains(&key), "never shown again");
        assert!(!fixture.audit_log()?.contains(&key), "never audited");
        assert!(
            !fs::read_to_string(fixture.state.dir().join("api_keys.json"))?.contains(&key),
            "only the hash is stored"
        );

        let revoked = fixture
            .post(
                &admin,
                "/ui/admin/api-keys/revoke",
                &[
                    ("object", "probe"),
                    ("confirm", "yes"),
                    ("confirm_name", "probe"),
                ],
            )
            .await?;
        assert_eq!(revoked.status(), StatusCode::OK, "revoked");
        assert_eq!(
            mcp_status(address, &key).await?,
            401,
            "refused without a restart"
        );
        server.abort();
        Ok(())
    }

    /// W1-16: a key whose table refresh fails after it was stored is still shown, once,
    /// in an uncached response, and never audited.
    #[tokio::test]
    async fn a_new_key_is_shown_once_even_when_the_table_refresh_fails() -> TestResult {
        let options = Options {
            breaking: true,
            ..Options::default()
        };
        let (fixture, _bridge) = Fixture::build("en", Vec::new(), &options)?;
        let admin = fixture.admin().await?;

        let created = fixture
            .post(
                &admin,
                "/ui/admin/api-keys",
                &[("name", "probe"), ("role", "viewer")],
            )
            .await?;

        assert_eq!(created.status(), StatusCode::OK, "the key dialog");
        assert_eq!(
            header_text(&created, header::CACHE_CONTROL.as_str()).as_deref(),
            Some("no-store, max-age=0"),
            "the response with the key is never stored"
        );
        let html = text(created).await?;
        let key = input_value(&html, "api-key-value").ok_or("the key is shown")?;
        assert_eq!(html.matches(key.as_str()).count(), 1, "shown once");
        assert!(
            !html.contains("id=\"admin-region\""),
            "no table from a failed refresh"
        );
        assert!(!fixture.audit_log()?.contains(&key), "never audited");
        Ok(())
    }

    /// W1-09: a storage failure on the users, roles, API-key and account handlers answers
    /// with the localized 500 page, not an empty body.
    #[tokio::test]
    async fn storage_failures_answer_with_the_localized_error_page() -> TestResult {
        let fixture = Fixture::new("en", Vec::new())?;
        fixture.add_user("bob", "viewer")?;
        let admin = fixture.admin().await?;
        fs::write(fixture.state.dir().join("api_keys.json"), "{")?;
        let keys = fixture
            .get("/ui/admin/api-keys/revoke?name=probe", &admin.cookie)
            .await?;
        let roles = fixture
            .post(
                &admin,
                "/ui/admin/roles",
                &[("name", "lab"), ("scope", "lab-*"), ("read", "on")],
            )
            .await?;
        fs::write(fixture.state.dir().join("users.json"), "{")?;
        let users = fixture
            .post(&admin, "/ui/admin/users/disable", &[("name", "bob")])
            .await?;
        let account = fixture
            .post(&admin, "/ui/account/locale", &[("locale", "de")])
            .await?;

        for (handler, response) in [
            ("keys", keys),
            ("roles", roles),
            ("users", users),
            ("account", account),
        ] {
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{handler}"
            );
            assert!(
                text(response)
                    .await?
                    .contains(&en(keys::WEB_ERROR_INTERNAL_TITLE)),
                "{handler}: the localized error page"
            );
        }
        Ok(())
    }

    /// W1-11: a role form naming a permission this server does not know is refused with
    /// the form's permission error; nothing is stored or reloaded.
    #[tokio::test]
    async fn a_role_form_with_an_unknown_permission_is_refused() -> TestResult {
        let fixture = Fixture::new("en", Vec::new())?;
        let admin = fixture.admin().await?;

        let response = fixture
            .post(
                &admin,
                "/ui/admin/roles",
                &[
                    ("name", "lab"),
                    ("scope", "lab-*"),
                    ("read", "on"),
                    ("sudo", "on"),
                ],
            )
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let form = text(response).await?;
        assert!(
            form.contains("id=\"role-permissions-error\""),
            "the permission error of the re-rendered form"
        );
        assert!(
            form.contains("name=\"read\" value=\"on\" checked"),
            "the known permissions stay ticked"
        );
        assert!(
            !load_roles(&fixture.state)?
                .iter()
                .any(|role| role.name == "lab"),
            "nothing stored"
        );
        assert_eq!(fixture.reload.rbac.load(Ordering::SeqCst), 0, "no reload");
        Ok(())
    }

    /// A fixture with audited changes (a web user creation, an MCP save on `lab-1`) and
    /// the auditor `ann` (`Read` + `ViewAudit`) signed in.
    async fn audited() -> Result<(Fixture, Browser), Box<dyn Error + Send + Sync>> {
        let auditor = role(
            "auditor",
            &[Permission::Read, Permission::ViewAudit],
            &["*"],
        );
        let fixture = Fixture::new("en", vec![auditor])?;
        fixture.add_user("ann", "auditor")?;
        let admin = fixture.admin().await?;
        let created = fixture
            .post(
                &admin,
                "/ui/admin/users",
                &[
                    ("username", "bob"),
                    ("password", "secret initial words"),
                    ("role", "viewer"),
                    ("locale", "en"),
                ],
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "a change to audit");
        let save = AuditEvent::new(
            0,
            Actor::new(ActorKind::Mcp, "probe".to_owned()),
            "router.save".to_owned(),
        )
        .with_router("lab-1".to_owned())
        .with_result("success".to_owned(), "mcp-1".to_owned());
        drop(fixture.audit.append(save).await?);
        let (reader, _) = fixture.sign_in("ann", PASSWORD, "/ui/admin/audit").await?;
        Ok((fixture, reader))
    }

    #[tokio::test]
    async fn the_audit_log_is_for_view_audit_and_filters_entries() -> TestResult {
        let (fixture, reader) = audited().await?;
        let landing = fixture.get("/ui/admin", &reader.cookie).await?;
        assert_eq!(
            header_text(&landing, header::LOCATION.as_str()).as_deref(),
            Some("/ui/admin/audit"),
            "the landing opens the audit log"
        );
        for refused in ["/ui/admin/users", "/ui/admin/server"] {
            let response = fixture.get(refused, &reader.cookie).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{refused}");
        }

        let entries = fixture.audit_log()?.lines().count().to_string();
        let all = text(fixture.get("/ui/admin/audit", &reader.cookie).await?).await?;
        assert!(
            all.contains(&en_with(
                keys::WEB_ADMIN_AUDIT_INTACT,
                &[("count", &entries)]
            )),
            "verified"
        );
        for expected in ["admin.user_create", "web.login", "router.save"] {
            assert!(all.contains(expected), "lists {expected}");
        }
        let empty = en(keys::WEB_ADMIN_AUDIT_EMPTY);
        let date = en(keys::WEB_ADMIN_ERROR_DATE);
        for (query, shown, hidden) in [
            ("action=admin.", "admin.user_create", "router.save"),
            ("router=lab-1", "router.save", "admin.user_create"),
            ("actor=PRO", "router.save", "web.login"),
            (
                "from=1970-01-01&to=1970-01-01",
                "router.save",
                empty.as_str(),
            ),
            ("from=2099-01-01", empty.as_str(), "router.save"),
            ("from=1970-13", date.as_str(), empty.as_str()),
        ] {
            let path = format!("/ui/admin/audit?{query}");
            let html = text(fixture.get(&path, &reader.cookie).await?).await?;
            assert!(html.contains(shown), "{query} shows {shown}");
            assert!(!html.contains(hidden), "{query} hides {hidden}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_audit_export_is_filtered_jsonl_and_tampering_shows() -> TestResult {
        let (fixture, reader) = audited().await?;
        let export = fixture
            .get("/ui/admin/audit/export?action=admin.", &reader.cookie)
            .await?;
        assert_eq!(export.status(), StatusCode::OK, "export");
        assert_eq!(
            header_text(&export, header::CONTENT_TYPE.as_str()).as_deref(),
            Some("application/x-ndjson; charset=utf-8"),
            "JSONL"
        );
        assert!(
            header_text(&export, header::CONTENT_DISPOSITION.as_str())
                .is_some_and(|value| value.starts_with("attachment;")),
            "a download"
        );
        let jsonl = text(export).await?;
        assert!(!jsonl.contains("secret initial words"), "no password");
        let lines: Vec<serde_json::Value> = jsonl
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert!(!lines.is_empty(), "entries exported");
        assert!(
            lines.iter().all(|line| {
                line.get("action")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|action| action.starts_with("admin."))
            }),
            "filtered: {jsonl}"
        );
        assert!(
            fixture.audit_log()?.contains("\"admin.audit_export\""),
            "the export is audited"
        );

        let file = fixture.state.dir().join("audit.jsonl");
        let tampered = fs::read_to_string(&file)?.replacen("\"bob\"", "\"mallory\"", 1);
        let seq = tampered
            .lines()
            .find(|line| line.contains("\"mallory\""))
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()?
            .and_then(|entry| entry.get("seq").and_then(serde_json::Value::as_u64))
            .ok_or("the tampered entry has a seq")?
            .to_string();
        fs::write(&file, tampered)?;
        let broken = text(fixture.get("/ui/admin/audit", &reader.cookie).await?).await?;
        assert!(
            broken.contains(&en_with(keys::WEB_ADMIN_AUDIT_BROKEN, &[("value", &seq)])),
            "tampering shows"
        );
        assert!(broken.contains("mallory"), "the broken log is still listed");
        Ok(())
    }

    /// SEC1-08: a viewer scoped to router `lab-a` sees neither another router's entries nor
    /// the entries without a router, on the page and in the export.
    ///
    /// An unscoped viewer sees every entry.
    #[tokio::test]
    async fn a_router_scoped_audit_viewer_sees_only_its_routers_entries() -> TestResult {
        let scoped = role(
            "auditor-a",
            &[Permission::Read, Permission::ViewAudit],
            &["lab-a"],
        );
        let unscoped = role(
            "auditor",
            &[Permission::Read, Permission::ViewAudit],
            &["*"],
        );
        let fixture = Fixture::new("en", vec![scoped, unscoped])?;
        fixture.add_user("sam", "auditor-a")?;
        fixture.add_user("ann", "auditor")?;
        for (router, action) in [("lab-a", "router.save"), ("lab-b", "router.reboot")] {
            let event = AuditEvent::new(
                0,
                Actor::new(ActorKind::Mcp, "probe".to_owned()),
                action.to_owned(),
            )
            .with_router(router.to_owned())
            .with_result("success".to_owned(), "mcp-1".to_owned());
            drop(fixture.audit.append(event).await?);
        }
        let note = AuditEvent::new(
            0,
            Actor::new(ActorKind::Cli, "probe".to_owned()),
            "system.note".to_owned(),
        )
        .with_result("success".to_owned(), "cli-1".to_owned());
        drop(fixture.audit.append(note).await?);

        let (scoped_browser, _) = fixture.sign_in("sam", PASSWORD, "/ui/admin/audit").await?;
        let page = text(
            fixture
                .get("/ui/admin/audit", &scoped_browser.cookie)
                .await?,
        )
        .await?;
        assert!(page.contains("router.save"), "its own router's entry");
        for hidden in ["router.reboot", "system.note", "web.login"] {
            assert!(!page.contains(hidden), "the page hides {hidden}");
        }
        let jsonl = text(
            fixture
                .get("/ui/admin/audit/export", &scoped_browser.cookie)
                .await?,
        )
        .await?;
        assert!(jsonl.contains("router.save"), "the export has its entry");
        for hidden in ["router.reboot", "system.note", "web.login"] {
            assert!(!jsonl.contains(hidden), "the export hides {hidden}");
        }

        let (full_browser, _) = fixture.sign_in("ann", PASSWORD, "/ui/admin/audit").await?;
        let full_page = text(fixture.get("/ui/admin/audit", &full_browser.cookie).await?).await?;
        for shown in ["router.save", "router.reboot", "system.note", "web.login"] {
            assert!(full_page.contains(shown), "an unscoped viewer sees {shown}");
        }
        let full_jsonl = text(
            fixture
                .get("/ui/admin/audit/export", &full_browser.cookie)
                .await?,
        )
        .await?;
        assert!(full_jsonl.contains("system.note"), "and exports it");
        Ok(())
    }

    /// W1-08: the export body is a stream of one chunk per entry, not one string built
    /// from the whole log, and a view after an append shows the appended entry.
    #[tokio::test]
    async fn the_audit_export_streams_and_a_new_entry_shows_at_once() -> TestResult {
        let (fixture, reader) = audited().await?;
        let before = fixture.audit_log()?.lines().count();
        let export = fixture
            .get("/ui/admin/audit/export", &reader.cookie)
            .await?;
        let chunks: Vec<_> = export.into_body().into_data_stream().collect().await;
        assert!(
            chunks.len() >= before,
            "one chunk per entry: {}",
            chunks.len()
        );
        for chunk in chunks {
            assert!(chunk?.ends_with(b"\n"), "each chunk is one JSONL line");
        }

        let event = AuditEvent::new(
            0,
            Actor::new(ActorKind::Mcp, "probe".to_owned()),
            "router.reboot".to_owned(),
        )
        .with_router("lab-1".to_owned())
        .with_result("success".to_owned(), "mcp-2".to_owned());
        drop(fixture.audit.append(event).await?);
        let entries = fixture.audit_log()?.lines().count().to_string();
        let page = text(fixture.get("/ui/admin/audit", &reader.cookie).await?).await?;
        assert!(page.contains("router.reboot"), "the appended entry shows");
        assert!(
            page.contains(&en_with(
                keys::WEB_ADMIN_AUDIT_INTACT,
                &[("count", &entries)]
            )),
            "and is verified"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_server_page_summarizes_the_configuration_without_secrets() -> TestResult {
        let directory = TempDir::new()?;
        let config_file = directory.path().join("kcc.toml");
        fs::write(
            &config_file,
            "[web]\npublic_url = \"https://kcc.example.net\"\n\n[[routers]]\nname = \"lab-1\"\nurl = \"http://192.168.1.1\"\nlogin = \"admin\"\npassword_file = \"/run/secrets/router-password-file\"\n",
        )?;
        let options = Options {
            transport: false,
            breaking: false,
            config: Config::load(&config_file)?,
        };
        let (fixture, _) = Fixture::build("en", Vec::new(), &options)?;
        let admin = fixture.admin().await?;

        let page = fixture.get("/ui/admin/server", &admin.cookie).await?;
        assert_eq!(page.status(), StatusCode::OK, "server page");
        let html = text(page).await?;
        let state_dir = fixture.state.dir().display().to_string();
        let routers = format!("{}</dt><dd>1</dd>", en(keys::WEB_ADMIN_SERVER_ROUTERS));
        let writable = format!(
            "{}</dt><dd>{}</dd>",
            en(keys::WEB_ADMIN_SERVER_STATE_WRITABLE),
            en(keys::COMMON_YES)
        );
        let writer = format!(
            "{}</dt><dd>{}</dd>",
            en(keys::WEB_ADMIN_SERVER_AUDIT_WRITER),
            en(keys::WEB_ADMIN_SERVER_RUNNING)
        );
        for expected in [
            ">9.9.9</dd>",
            "https://kcc.example.net/",
            routers.as_str(),
            writable.as_str(),
            writer.as_str(),
            ">5.1</td>",
            state_dir.as_str(),
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        for secret in ["router-password-file", "/run/secrets", "admin</dd>"] {
            assert!(!html.contains(secret), "leaked {secret}");
        }
        Ok(())
    }
}
