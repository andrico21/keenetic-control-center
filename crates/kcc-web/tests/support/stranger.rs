//! A stranger's requests on another account's wizard run: every route that takes a run id
//! must answer 404 and leave the run as it was.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::fs;

use axum::http::StatusCode;

use super::{outcome::TestResult, web::Fixture};

/// How a route is requested.
#[derive(Debug, Clone, Copy)]
enum Method {
    /// `GET`.
    Get,
    /// A form `POST`.
    Post,
    /// A `multipart/form-data` `POST`.
    Multipart,
}

/// One route under a run's page: method, path after the page, and form fields.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Route<'route> {
    /// How it is requested.
    method: Method,
    /// The path after the run's page; empty for the page itself.
    path: &'route str,
    /// The form fields of a `POST`.
    fields: &'route [(&'route str, &'route str)],
}

impl<'route> Route<'route> {
    /// `GET {page}{path}`.
    pub(crate) const fn get(path: &'route str) -> Self {
        Self {
            method: Method::Get,
            path,
            fields: &[],
        }
    }

    /// A form `POST {page}{path}` of `fields`.
    pub(crate) const fn post(
        path: &'route str,
        fields: &'route [(&'route str, &'route str)],
    ) -> Self {
        Self {
            method: Method::Post,
            path,
            fields,
        }
    }

    /// A multipart `POST {page}{path}` of `fields`.
    pub(crate) const fn multipart(
        path: &'route str,
        fields: &'route [(&'route str, &'route str)],
    ) -> Self {
        Self {
            method: Method::Multipart,
            path,
            fields,
        }
    }
}

/// Sends every route of `routes` under `page` as `stranger` and fails, naming each,
/// unless every one answers 404.
// NOT cancel-safe: a request may be served after cancellation.
pub(crate) async fn strangers_refused(
    fixture: &Fixture,
    (page, stranger): (&str, &str),
    routes: &[Route<'_>],
) -> TestResult {
    let browser = fixture.login(stranger).await?;
    let mut reached = Vec::new();
    for route in routes {
        let path = format!("{page}{}", route.path);
        let response = match route.method {
            Method::Get => fixture.get(&path, &browser).await?,
            Method::Post => fixture.post_form(&path, &browser, route.fields).await?,
            Method::Multipart => {
                fixture
                    .post_multipart(&path, &browser, (route.fields, None))
                    .await?
            }
        };
        if response.status() != StatusCode::NOT_FOUND {
            reached.push(format!("{:?} {path}: {}", route.method, response.status()));
        }
    }
    if reached.is_empty() {
        Ok(())
    } else {
        Err(format!("a stranger was not refused: {reached:?}").into())
    }
}

/// Every file of the run at `page` with its bytes, by name.
pub(crate) fn run_files(fixture: &Fixture, page: &str) -> TestResult<BTreeMap<String, Vec<u8>>> {
    let id = page.rsplit('/').next().ok_or("no run id")?;
    let directory = fixture.state_dir().join("migrations").join(id);
    let mut files = BTreeMap::new();
    for listed in fs::read_dir(directory)? {
        let entry = listed?;
        let name = entry.file_name().to_string_lossy().into_owned();
        drop(files.insert(name, fs::read(entry.path())?));
    }
    Ok(files)
}
