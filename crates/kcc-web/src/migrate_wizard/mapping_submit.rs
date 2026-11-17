//! Step 3's submit: every map entry checked against the target's objects, then the maps
//! stored and the review opened.

use alloc::{collections::BTreeSet, sync::Arc};

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::maps::{InterfaceMap, PortMap, RadioMap};
use serde_json::json;

use super::{
    access::{Migration as _, Visit},
    kinds::{Maps, Step},
    mapping::Panel,
    maps::{Kind, Refusal as MapRefusal, Sides, pairs},
    record::Record,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        request::last,
        respond::{self, Answer},
    },
    wizard::{flow::Flow as _, names::map_of, screen, service::Wizards, services::Services},
};

/// `POST /ui/migrate/{id}/mapping`: checks the maps and moves on to the review.
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with the rows' errors (422).
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services: Services<'_> = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Mapping {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let analysis = match visit.analysis().await {
        Ok(found) => found,
        Err(_problem) => return Err(respond::unprocessable(&Panel::new(&visit).await).into()),
    };
    let hardware = visit.hardware(&analysis).await;
    let sides = Sides::new(hardware.as_deref(), analysis.source(), analysis.target());
    let current = visit
        .record()
        .maps()
        .cloned()
        .unwrap_or_else(|| sides.propose());
    let (maps, refused) = checked(&sides, &current, &form, locale);
    if let Some(refusals) = refused {
        let mut panel = Panel::new(&visit).await;
        panel.fill(&sides, &maps, locale);
        return Err(respond::unprocessable(&panel.with_errors(refusals)).into());
    }
    let mapped = [
        &maps.ports().entries,
        &maps.radios().entries,
        &maps.interfaces().entries,
    ]
    .iter()
    .map(|entries| {
        entries
            .iter()
            .filter(|entry| entry.target.as_deref() != Some(entry.source.as_str()))
            .count()
    })
    .sum::<usize>();
    visit.record_mut().set_maps(maps);
    if let Err(error) = visit.save().await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let router = visit.record().target().unwrap_or_default().to_owned();
    Audit::on_router("web.migrate_mapping", &router, id)
        .with_params(json!({ "renamed": mapped }))
        .append(&state, &user, "saved")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The maps `form` chose, each row checked against `sides` from `current`, and every
/// row's error when any row was refused.
fn checked(
    sides: &Sides<'_>,
    current: &Maps,
    form: &[(String, String)],
    locale: Locale,
) -> (Maps, Option<Vec<Vec<String>>>) {
    let value =
        |field: &str| last(form, field).map_or_else(String::new, |chosen| chosen.trim().to_owned());
    let mut failed = false;
    let mut decided = Vec::new();
    let mut errors = Vec::new();
    for (kind, entries) in [
        (Kind::Port, pairs(&current.ports().entries)),
        (Kind::Radio, pairs(&current.radios().entries)),
        (Kind::Interface, pairs(&current.interfaces().entries)),
    ] {
        let mut taken = BTreeSet::new();
        let mut kind_pairs = Vec::new();
        let mut kind_errors = Vec::new();
        for (index, (source, _)) in entries.iter().enumerate() {
            let chosen = value(&format!("{}-{index}", kind.prefix()));
            match sides.check(kind, source, &chosen, &taken) {
                Ok(target) => {
                    if let Some(name) = &target {
                        let _: bool = taken.insert(name.clone());
                    }
                    kind_pairs.push((source.clone(), target));
                    kind_errors.push(String::new());
                }
                Err(refusal) => {
                    failed = true;
                    kind_errors.push(refusal_text(refusal, &chosen, locale));
                    kind_pairs.push((source.clone(), Some(chosen)));
                }
            }
        }
        decided.push(kind_pairs);
        errors.push(kind_errors);
    }
    let mut kinds = decided.into_iter();
    let maps = Maps::new(
        map_of::<PortMap, _>(kinds.next().unwrap_or_default()),
        map_of::<RadioMap, _>(kinds.next().unwrap_or_default()),
        map_of::<InterfaceMap, _>(kinds.next().unwrap_or_default()),
    );
    (maps, failed.then_some(errors))
}

/// The error text of a refused map entry naming `value`.
fn refusal_text(refusal: MapRefusal, value: &str, locale: Locale) -> String {
    let key = match refusal {
        MapRefusal::Unknown => keys::WEB_MIGRATE_MAP_ERROR_UNKNOWN,
        MapRefusal::Taken => keys::WEB_MIGRATE_MAP_ERROR_TAKEN,
        MapRefusal::Band => keys::WEB_MIGRATE_MAP_ERROR_BAND,
        MapRefusal::Name => keys::WEB_MIGRATE_MAP_ERROR_NAME,
        MapRefusal::OtherKind => keys::WEB_MIGRATE_MAP_ERROR_KIND,
    };
    let mut args = FluentArgs::new();
    args.set("name", value.to_owned());
    tr(locale, key, Some(&args))
}
