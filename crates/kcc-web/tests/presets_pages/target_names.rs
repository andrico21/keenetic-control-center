//! Step 2 of a preset run names a labelled target router by its name.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::{
        flow::{DNS_LINES, capture, seed, start},
        setup,
        support::{
            outcome::TestResult,
            page::{html, text},
        },
    };

    /// Todo 11: the target picker shows a labelled router's name and sends its id.
    #[tokio::test]
    async fn the_target_picker_names_a_labelled_router() -> TestResult {
        let name = "Lab Office";
        let fixture = setup::fixture().await?;
        fixture.label("lab-1", name).await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let page = start(&fixture, &admin, &id).await?;
        let step = text(fixture.get(&page, &admin).await?).await?;
        // The header's router switcher lists the same option, so only the step's own
        // select counts.
        let picker = step
            .split_once("id=\"target-router\"")
            .and_then(|(_, rest)| rest.split_once("</select>"))
            .map(|(select, _)| select)
            .ok_or("the step has no target picker")?;
        let option = format!(">{}</option>", html(name));
        assert!(
            picker.contains(&format!("<option value=\"lab-1\"{option}"))
                || picker.contains(&format!("<option value=\"lab-1\" selected{option}")),
            "the picker names the router and sends its id: {picker}"
        );
        Ok(())
    }
}
