//! SSH transport to a router's Entware userland and the closed Entware command set.
//!
//! kcc reaches Entware's dropbear only through this crate, and only in one shape:
//!
//! - [`transport::AdmittedAddresses::admit`] resolves the router's host through the
//!   outbound policy (`kcc_rci::OutboundPolicy::admit_ssh`); nothing else yields an
//!   address this crate dials.
//! - [`pool::SshPool`] hands out one [`pool::Slot`] per router at a time (four in
//!   total); a slot probes a host key ([`pool::Slot::probe_host_key`]) or opens a
//!   [`session::Session`] with a mandatory [`keys::HostKeyPin`]
//!   ([`pool::Slot::connect`]). A host key that differs from the pin byte for byte ends
//!   the handshake before any authentication.
//! - [`session::Session::run`] executes one [`command::EntwareCommand`]. Every variant
//!   carries arguments parsed by the token grammars in [`grammar`]; no function of this
//!   crate takes command text.
//! - [`parse`] reads the listings and the `rc.func` exit codes of the outputs.
//!
//! Passwords, private keys and command output never reach a log record, an error or a
//! `Debug` rendering.
// `dead_code_pub_in_binary` fires on the public API only in the lib unit-test
// binary; rustc accepts an expect for it at crate level alone.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

extern crate alloc;

pub mod command;
pub mod error;
pub mod grammar;
pub mod keys;
pub mod parse;
pub mod pool;
pub mod session;
pub mod transport;
