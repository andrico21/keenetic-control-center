//! What the Web UI integration tests share: the Web UI built over fake routers, a
//! signed-in browser's requests, reading the answers, and the table drivers of the page
//! contracts every router page keeps.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

pub(crate) mod asked;
pub(crate) mod base;
pub(crate) mod build;
pub(crate) mod outcome;
pub(crate) mod page;
pub(crate) mod refusal;
pub(crate) mod typed_name;
pub(crate) mod web;
