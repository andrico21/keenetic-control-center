//! Tests of the fake Entware SSH server, driven by a raw russh client over loopback.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, net::SocketAddr, time::Duration};
    use std::sync::{Mutex, PoisonError};

    use kcc_testkit::entware_ssh::{Config, FakeEntwareSsh, Fault, Service, USER};
    use russh::{
        ChannelMsg, client,
        keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
    };
    use tokio::{net::TcpStream, time::timeout};

    extern crate alloc;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// The `PATH` prologue every command of the closed command set starts with.
    const PROLOGUE: &str = "PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin; export PATH; ";

    /// Bound for every exchange with the fake.
    const LIMIT: Duration = Duration::from_secs(20);

    /// rc.func's `check` output: white label, twelve spaces, the coloured result word.
    fn check_output(process: &str, colour: &str, word: &str) -> String {
        format!(
            "\u{1b}[1;37m Checking {process}... {}\u{1b}[{colour}m {word} \u{1b}[m\n",
            " ".repeat(12)
        )
    }

    /// Client handler recording the host key the server presented.
    struct Recorder {
        /// The last presented host key.
        seen: Arc<Mutex<Option<PublicKey>>>,
    }

    impl client::Handler for Recorder {
        type Error = russh::Error;

        #[expect(
            clippy::unused_async_trait_impl,
            reason = "async is mandated by the russh handler trait"
        )]
        // cancel-safe: it has no await point.
        async fn check_server_key(
            &mut self,
            server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            let PublicKeyOrCertificate::PublicKey {
                key: presented,
                hash_alg: _,
            } = server_public_key
            else {
                return Ok(false);
            };
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(presented.clone());
            Ok(true)
        }
    }

    /// One finished command as the client saw it.
    #[derive(Debug, Default)]
    struct Output {
        /// Standard output bytes.
        stdout: Vec<u8>,
        /// Standard error bytes.
        stderr: Vec<u8>,
        /// Exit status; `None` when the server sent none.
        exit: Option<u32>,
    }

    impl Output {
        /// Standard output as text.
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }
    }

    /// A connected client with the host key it saw.
    struct Connected {
        /// The russh client session.
        session: client::Handle<Recorder>,
        /// Host key the server presented.
        host_key: Option<PublicKey>,
    }

    /// Connects without authenticating.
    // NOT cancel-safe: a dropped handshake leaves a half-open connection.
    async fn connect(address: SocketAddr) -> TestResult<Connected> {
        let seen = Arc::new(Mutex::new(None));
        let stream = TcpStream::connect(address).await?;
        let session = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            Recorder {
                seen: Arc::clone(&seen),
            },
        )
        .await?;
        let host_key = seen.lock().unwrap_or_else(PoisonError::into_inner).take();
        Ok(Connected { session, host_key })
    }

    /// Connects and authenticates with the default password.
    // NOT cancel-safe: see `connect`.
    async fn login(address: SocketAddr) -> TestResult<client::Handle<Recorder>> {
        let mut connected = connect(address).await?;
        let result = connected
            .session
            .authenticate_password(USER, "keenetic")
            .await?;
        assert!(result.success(), "default password accepted");
        Ok(connected.session)
    }

    /// Runs `command` on a new channel and collects everything until the channel closes.
    // NOT cancel-safe: a dropped exchange leaves an open channel.
    async fn exec(session: &client::Handle<Recorder>, command: &str) -> TestResult<Output> {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut output = Output::default();
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = &message {
                output.stdout.extend_from_slice(data);
            }
            if let ChannelMsg::ExtendedData { data, ext: 1 } = &message {
                output.stderr.extend_from_slice(data);
            }
            if let ChannelMsg::ExitStatus { exit_status } = message {
                output.exit = Some(exit_status);
            }
        }
        Ok(output)
    }

    /// A service command as the closed command set renders it.
    fn service(name: &str, action: &str) -> String {
        format!("{PROLOGUE}'/opt/etc/init.d/{name}' {action}")
    }

    /// The fake with two packages and three services.
    fn config() -> Config {
        Config::default()
            .installed("entware-opt", "227000-3")
            .installed("opkg", "2024.10.16~38eccbb1-1")
            .upgradable("opkg", "2024.10.16~38eccbb1-2")
            .installable("mc", "4.8.31-1")
            .service("S51dropbear", Service::new("dropbear").running())
            .service("S80nginx", Service::new("nginx"))
            .service("S99off", Service::new("off").disabled())
    }

    /// Todo 6: password authentication counts attempts, then `opkg list-installed` lists
    /// the installed packages as `name - version` and exits 0.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn password_auth_then_list_installed() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        timeout(LIMIT, async {
            let mut connected = connect(address).await?;
            let refused = connected
                .session
                .authenticate_password(USER, format!("{}-wrong", "keenetic"))
                .await?;
            assert!(!refused.success(), "wrong password refused");
            let accepted = connected
                .session
                .authenticate_password(USER, "keenetic")
                .await?;
            assert!(accepted.success(), "default password accepted");
            let listed = exec(
                &connected.session,
                &format!("{PROLOGUE}/opt/bin/opkg list-installed"),
            )
            .await?;
            assert_eq!(listed.exit, Some(0));
            assert_eq!(
                listed.text(),
                "entware-opt - 227000-3\nopkg - 2024.10.16~38eccbb1-1\n"
            );
            let upgradable = exec(
                &connected.session,
                &format!("{PROLOGUE}/opt/bin/opkg list-upgradable"),
            )
            .await?;
            assert_eq!(
                upgradable.text(),
                "opkg - 2024.10.16~38eccbb1-1 - 2024.10.16~38eccbb1-2\n"
            );
            TestResult::Ok(())
        })
        .await??;
        let counters = handle.counters();
        assert_eq!(
            (
                counters.connections,
                counters.auth_attempts,
                counters.commands
            ),
            (1, 2, 2)
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: key authentication accepts a key listed in the in-memory `authorized_keys`
    /// and refuses any other key.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn key_auth_uses_authorized_keys() -> TestResult {
        let listed = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let line = format!("{} kcc:r1\n", listed.public_key().to_openssh()?);
        let (address, handle) = FakeEntwareSsh::spawn(config().authorized_keys(line)).await?;
        timeout(LIMIT, async {
            let mut connected = connect(address).await?;
            let refused = connected
                .session
                .authenticate_publickey(USER, PrivateKeyWithHashAlg::new(Arc::new(other), None))
                .await?;
            assert!(!refused.success(), "unlisted key refused");
            let accepted = connected
                .session
                .authenticate_publickey(USER, PrivateKeyWithHashAlg::new(Arc::new(listed), None))
                .await?;
            assert!(accepted.success(), "listed key accepted");
            TestResult::Ok(())
        })
        .await??;
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: `check` follows rc.func: `alive.` with exit 0, `dead.` with exit 1, both in
    /// rc.func's ANSI colours; an unknown action prints usage and exits 1.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn check_reports_alive_and_dead_in_ansi_colours() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        timeout(LIMIT, async {
            let session = login(address).await?;
            let alive = exec(&session, &service("S51dropbear", "check")).await?;
            assert_eq!(
                (alive.exit, alive.text()),
                (Some(0), check_output("dropbear", "1;32", "alive."))
            );
            let dead = exec(&session, &service("S80nginx", "check")).await?;
            assert_eq!(
                (dead.exit, dead.text()),
                (Some(1), check_output("nginx", "1;31", "dead."))
            );
            let usage = exec(&session, &service("S80nginx", "status")).await?;
            assert_eq!(usage.exit, Some(1));
            assert!(usage.text().contains(
                "Usage: /opt/etc/init.d/S80nginx (start|stop|restart|check|kill|reconfigure)"
            ));
            TestResult::Ok(())
        })
        .await??;
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: `start` of a disabled service exits 8 without starting it; `start` of an
    /// enabled one exits 0 and the next `check` is alive.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn start_of_disabled_service_exits_8() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        timeout(LIMIT, async {
            let session = login(address).await?;
            let refused = exec(&session, &service("S99off", "start")).await?;
            assert_eq!((refused.exit, refused.stdout.len()), (Some(8), 0));
            let started = exec(&session, &service("S80nginx", "start")).await?;
            assert_eq!(started.exit, Some(0));
            assert!(started.text().contains(" done. "));
            let check = exec(&session, &service("S80nginx", "check")).await?;
            assert_eq!(check.exit, Some(0));
            TestResult::Ok(())
        })
        .await??;
        assert_eq!(
            handle.service("S99off").map(|state| state.is_running()),
            Some(false)
        );
        assert_eq!(
            handle.service("S80nginx").map(|state| state.is_running()),
            Some(true)
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: `stop` of a stopped service is rc.func's `check && stop`: it prints `dead.`
    /// and exits 1.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn stop_of_stopped_service_exits_1() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        timeout(LIMIT, async {
            let session = login(address).await?;
            let stopped = exec(&session, &service("S80nginx", "stop")).await?;
            assert_eq!(
                (stopped.exit, stopped.text()),
                (Some(1), check_output("nginx", "1;31", "dead."))
            );
            let running = exec(&session, &service("S51dropbear", "stop")).await?;
            assert_eq!(running.exit, Some(0));
            TestResult::Ok(())
        })
        .await??;
        assert_eq!(
            handle
                .service("S51dropbear")
                .map(|state| state.is_running()),
            Some(false)
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: anything outside the templates answers 127, while a quoted argument reaches
    /// opkg as one literal word.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn unknown_command_exits_127() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        timeout(LIMIT, async {
            let session = login(address).await?;
            for command in [
                format!("{PROLOGUE}uname -a"),
                "/opt/bin/opkg list-installed".to_owned(),
                format!("{PROLOGUE}/opt/bin/opkg install mc"),
                format!("{PROLOGUE}/opt/bin/opkg install 'mc' 'opkg'"),
                service("S98missing", "start"),
                format!("{PROLOGUE}/opt/etc/init.d/S80nginx start"),
                service("S80nginx", "start; rm -rf /"),
                service("S80nginx", "start && id"),
                service("S80nginx", "start `id`"),
                service("S80nginx", "start $(id)"),
                service("S80nginx", "'start'"),
                service("S80nginx", "start\n"),
                service("S80nginx", "start stop"),
                service("S80nginx", "START"),
                service("S80nginx", ""),
                service("S80nginx", &"a".repeat(4096)),
            ] {
                let output = exec(&session, &command).await?;
                assert_eq!(output.exit, Some(127), "{command}");
                assert!(!output.stderr.is_empty(), "{command}");
            }
            let literal = exec(
                &session,
                &format!("{PROLOGUE}/opt/bin/opkg install 'mc;id'"),
            )
            .await?;
            assert_eq!(literal.exit, Some(255));
            let bogus = exec(&session, &service("S80nginx", "bogus")).await?;
            assert_eq!(bogus.exit, Some(1));
            let installed =
                exec(&session, &format!("{PROLOGUE}/opt/bin/opkg install 'mc'")).await?;
            assert_eq!(installed.exit, Some(0));
            TestResult::Ok(())
        })
        .await??;
        assert_eq!(
            handle.installed().get("mc").map(String::as_str),
            Some("4.8.31-1")
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: a replaced host key is what the next connection sees.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn host_key_swap_is_visible() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        let original = handle.host_key();
        assert_eq!(original.algorithm(), Algorithm::Ed25519);
        let before = timeout(LIMIT, connect(address)).await??;
        assert_eq!(before.host_key.as_ref(), Some(&original));
        let replaced = handle.replace_host_key();
        assert_ne!(replaced, original);
        assert_eq!(handle.host_key(), replaced);
        let after = timeout(LIMIT, connect(address)).await??;
        assert_eq!(after.host_key.as_ref(), Some(&replaced));
        assert_eq!(handle.counters().auth_attempts, 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 6: the fault switches: output over 256 KiB, no exit status, a hang, and a
    /// connection killed after N commands.
    // NOT cancel-safe: owns the fake through the test.
    #[tokio::test]
    async fn fault_switches() -> TestResult {
        let (address, handle) = FakeEntwareSsh::spawn(config()).await?;
        let list = format!("{PROLOGUE}/opt/bin/opkg list-installed");
        timeout(LIMIT, async {
            let session = login(address).await?;
            handle.set_fault(Some(Fault::HugeOutput));
            let huge = exec(&session, &list).await?;
            assert!(huge.stdout.len() > 256 * 1024);
            assert_eq!(huge.exit, Some(0));
            handle.set_fault(Some(Fault::NoExitStatus));
            let silent = exec(&session, &list).await?;
            assert_eq!(silent.exit, None);
            assert!(silent.text().starts_with("entware-opt - "));
            handle.set_fault(Some(Fault::Hang));
            assert!(
                timeout(Duration::from_millis(300), exec(&session, &list))
                    .await
                    .is_err(),
                "a hung command never finishes"
            );
            let served = handle.counters().commands;
            handle.set_fault(Some(Fault::KillAfter(served)));
            let killed = exec(&session, &list).await;
            assert!(
                !killed.is_ok_and(|output| output.exit.is_some()),
                "the connection dropped"
            );
            handle.set_fault(None);
            let fresh = login(address).await?;
            assert_eq!(exec(&fresh, &list).await?.exit, Some(0));
            TestResult::Ok(())
        })
        .await??;
        assert_eq!(handle.counters().connections, 2);
        handle.shutdown().await?;
        Ok(())
    }
}
