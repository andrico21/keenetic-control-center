//! Recursive JSON Schema projection of catalog metadata.

use serde_json::{Map, Value, json};

use crate::{
    Catalog,
    validate::{argument_schema, boolean_keyword_forms, child_names},
};

/// Builds the schema without changing the catalog's validation contract.
pub(super) fn generate(catalog: &Catalog, path: &str) -> Option<Value> {
    let command = catalog.lookup(path)?;
    let mut properties = Map::new();
    for (name, argument) in &command.arguments {
        drop(properties.insert(name.clone(), argument_schema(argument)));
        for keyword in boolean_keyword_forms(argument) {
            drop(properties.insert(keyword.to_owned(), json!({"type":"boolean"})));
        }
    }
    for child in child_names(catalog, path) {
        if let Some(schema) = generate(catalog, &format!("{path} {child}")) {
            drop(properties.insert(child, schema));
        }
    }
    if command.prefix_no {
        drop(properties.insert("no".to_owned(), json!({"const":true})));
    }
    Some(
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object", "properties":properties, "additionalProperties":false}),
    )
}
