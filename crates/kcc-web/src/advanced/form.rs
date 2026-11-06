//! The request form of one catalog command, generated from its JSON Schema
//! (`Catalog::to_json_schema`), and the request body read back from a submitted form.
//!
//! Every input is named `a.` plus its dotted path inside the body (`a.mac`,
//! `a.priority.priority`), so nested sub-commands become nested objects. Secret arguments
//! render as empty password inputs.

use kcc_i18n::locale::Locale;
use serde_json::Value;

use super::types;
use crate::page_kit::secret::is_secret;

/// Prefix of every generated input name.
pub(crate) const PREFIX: &str = "a.";

/// Deepest sub-command level the form shows.
const MAX_DEPTH: usize = 4;

/// Most input groups one form shows.
const MAX_GROUPS: usize = 120;

/// What a generated input accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Free text.
    Text,
    /// An integer.
    Number,
    /// One of a fixed set of words.
    Keyword,
    /// A boolean keyword such as `permit`: a checkbox.
    Flag,
    /// The `no` form of the command: a checkbox.
    Negate,
    /// A secret: an empty password input.
    Secret,
}

/// One generated input.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    /// Input name: [`PREFIX`] plus the dotted body path.
    name: String,
    /// Element id.
    id: String,
    /// The argument name, shown as the label.
    label: String,
    /// What the input accepts.
    kind: Kind,
    /// Keyword choices.
    options: Vec<String>,
    /// Localized description of the accepted values.
    hint: String,
}

/// The inputs of the command or of one nested sub-command.
#[derive(Debug, Clone)]
pub(crate) struct Group {
    /// Sub-command words below the command; empty for the command itself.
    title: String,
    /// Nesting level, 0 for the command.
    depth: usize,
    /// The group's inputs.
    fields: Vec<Field>,
}

/// The generated form: the command's own group first, then every sub-command.
#[derive(Debug, Clone, Default)]
pub(crate) struct Form {
    /// Input groups in document order.
    groups: Vec<Group>,
    /// Whether sub-commands beyond the limits were left out.
    clipped: bool,
}

impl Form {
    /// The form of the command whose schema is `schema`, with hints in `locale`.
    pub(crate) fn build(schema: &Value, locale: Locale) -> Self {
        let mut form = Self::default();
        walk(
            schema,
            &Walk {
                path: String::new(),
                depth: 0,
                locale,
            },
            &mut form,
        );
        form
    }

    /// The command's own inputs.
    pub(crate) fn own(&self) -> Option<&Group> {
        self.groups.first().filter(|group| group.depth == 0)
    }

    /// The sub-command groups.
    pub(crate) fn nested(&self) -> &[Group] {
        self.groups
            .get(usize::from(self.own().is_some())..)
            .unwrap_or_default()
    }

    /// Whether sub-commands were left out.
    pub(crate) const fn clipped(&self) -> bool {
        self.clipped
    }
}

/// Where the schema walk is.
struct Walk {
    /// Dotted body path of the current object.
    path: String,
    /// Nesting level.
    depth: usize,
    /// Hint language.
    locale: Locale,
}

/// Adds the group of the object schema `schema` and then its sub-commands to `form`.
fn walk(schema: &Value, at: &Walk, form: &mut Form) {
    if form.groups.len() >= MAX_GROUPS || at.depth > MAX_DEPTH {
        form.clipped = true;
        return;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };
    let mut fields = Vec::new();
    let mut negate = None;
    for (name, property) in properties {
        if property.get("properties").is_some() {
            continue;
        }
        let field = field(&at.path, name, property, at.locale);
        if field.kind == Kind::Negate {
            negate = Some(field);
        } else {
            fields.push(field);
        }
    }
    fields.extend(negate);
    form.groups.push(Group {
        title: at.path.replace('.', " "),
        depth: at.depth,
        fields,
    });
    for (name, property) in properties {
        if property.get("properties").is_none() {
            continue;
        }
        let child = Walk {
            path: join(&at.path, name),
            depth: at.depth.saturating_add(1),
            locale: at.locale,
        };
        walk(property, &child, form);
    }
}

/// The input of argument `name` with schema `property` in the object at `parent`.
fn field(parent: &str, name: &str, property: &Value, locale: Locale) -> Field {
    let path = join(parent, name);
    let options: Vec<String> = property
        .get("enum")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let integer = property.get("type").and_then(Value::as_str) == Some("integer");
    let kind = if property.get("const") == Some(&Value::Bool(true)) && name == "no" {
        Kind::Negate
    } else if property.get("const").is_some()
        || property.get("type").and_then(Value::as_str) == Some("boolean")
    {
        Kind::Flag
    } else if integer {
        Kind::Number
    } else if !options.is_empty() {
        Kind::Keyword
    } else if is_secret(name) {
        Kind::Secret
    } else {
        Kind::Text
    };
    Field {
        id: format!("arg-{}", path.replace('.', "-")),
        name: format!("{PREFIX}{path}"),
        label: name.to_owned(),
        hint: types::hint(property, kind, locale),
        kind,
        options,
    }
}

/// Joins a dotted path and one more member name.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}.{name}")
    }
}

impl Group {
    /// Sub-command words below the command; empty for the command itself.
    pub(crate) fn title(&self) -> &str {
        &self.title
    }

    /// Nesting level, 0 for the command.
    pub(crate) const fn depth(&self) -> usize {
        self.depth
    }

    /// The group's inputs.
    pub(crate) fn fields(&self) -> &[Field] {
        &self.fields
    }
}

impl Field {
    /// Input name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Element id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The argument name shown as the label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// The `type` attribute of a text-like input.
    pub(crate) const fn input_type(&self) -> &'static str {
        match self.kind {
            Kind::Secret => "password",
            Kind::Number | Kind::Text | Kind::Keyword | Kind::Flag | Kind::Negate => "text",
        }
    }

    /// The `inputmode` of a text-like input.
    pub(crate) const fn input_mode(&self) -> &'static str {
        match self.kind {
            Kind::Number => "numeric",
            Kind::Text | Kind::Secret | Kind::Keyword | Kind::Flag | Kind::Negate => "text",
        }
    }

    /// Whether the input is a checkbox.
    pub(crate) const fn checkbox(&self) -> bool {
        matches!(self.kind, Kind::Flag | Kind::Negate)
    }

    /// Whether the input is a select.
    pub(crate) const fn select(&self) -> bool {
        matches!(self.kind, Kind::Keyword)
    }

    /// Whether the input is the command's `no` form.
    pub(crate) const fn negate(&self) -> bool {
        matches!(self.kind, Kind::Negate)
    }

    /// Whether the input is write-only.
    pub(crate) const fn secret(&self) -> bool {
        matches!(self.kind, Kind::Secret)
    }

    /// Keyword choices.
    pub(crate) fn options(&self) -> &[String] {
        &self.options
    }

    /// Localized description of the accepted values.
    pub(crate) fn hint(&self) -> &str {
        &self.hint
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::locale::Locale;
    use serde_json::{Value, json};

    use super::{Form, Kind};

    /// The schema shape `Catalog::to_json_schema` gives `ip hotspot host`.
    fn schema() -> Value {
        json!({"type":"object","properties":{
            "access":{"enum":["deny","permit"],"type":"string"},
            "mac":{"pattern":"^x$","type":"string"},
            "no":{"const":true},
            "permit":{"type":"boolean"},
            "priority":{"type":"object","properties":{
                "priority":{"type":"integer","minimum":1,"maximum":7},
                "no":{"const":true}}},
            "password":{"type":"string"}}})
    }

    #[test]
    fn forms_have_typed_inputs_and_nested_fieldsets() {
        let form = Form::build(&schema(), Locale::En);
        let own = form.own().map(|group| {
            group
                .fields()
                .iter()
                .map(|field| (field.name().to_owned(), field.kind))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            own,
            Some(vec![
                ("a.access".to_owned(), Kind::Keyword),
                ("a.mac".to_owned(), Kind::Text),
                ("a.password".to_owned(), Kind::Secret),
                ("a.permit".to_owned(), Kind::Flag),
                ("a.no".to_owned(), Kind::Negate),
            ]),
            "own inputs, the no form last"
        );
        let nested: Vec<(&str, usize)> = form
            .nested()
            .iter()
            .map(|group| (group.title(), group.depth()))
            .collect();
        assert_eq!(nested, [("priority", 1)], "sub-command fieldset");
        assert!(!form.clipped(), "nothing left out");
    }
}
