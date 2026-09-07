//! Docker `filters` query-param parsing, shared by every list endpoint.
//!
//! The wire shape is `{"key":["v1","v2"]}`. Parsing is total and lenient:
//! anything that is not a JSON object of string-or-string-list values
//! degrades to empty (callers then apply their own strict key checks and
//! return 400 for unknown keys). Totality is what the fuzzer pins.

use std::collections::HashMap;

/// Parse a `filters` query value into key → values. Never fails.
pub fn parse_filters(raw: &Option<String>) -> HashMap<String, Vec<String>> {
    let Some(s) = raw.as_deref() else {
        return HashMap::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return HashMap::new();
    };
    let serde_json::Value::Object(map) = v else {
        return HashMap::new();
    };
    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        let vals = match v {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect(),
            serde_json::Value::String(s) => vec![s],
            _ => Vec::new(),
        };
        out.insert(k, vals);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_shape() {
        let m = parse_filters(&Some(r#"{"status":["running"],"label":["a=b"]}"#.into()));
        assert_eq!(m["status"], vec!["running".to_string()]);
        assert_eq!(m["label"], vec!["a=b".to_string()]);
    }

    #[test]
    fn degenerate_inputs_degrade_to_empty() {
        for raw in [
            None,
            Some("".to_string()),
            Some("not json".to_string()),
            Some("[1,2]".to_string()),
            Some("\"str\"".to_string()),
            Some("42".to_string()),
            Some("null".to_string()),
        ] {
            assert!(parse_filters(&raw).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn non_string_values_filtered() {
        let m = parse_filters(&Some(r#"{"a":[1,true,null,"x"],"b":"solo","c":{}}"#.into()));
        assert_eq!(m["a"], vec!["x".to_string()]);
        assert_eq!(m["b"], vec!["solo".to_string()]);
        assert!(m["c"].is_empty());
    }
}
