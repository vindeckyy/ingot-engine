//! Serde helpers for Docker API tolerance:
//! - the docker CLI sends `null` for unset arrays/maps
//! - query strings use `1`/`0` for booleans (and sometimes true/false)

use serde::{Deserialize, Deserializer};

pub fn null_to_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v: Option<Vec<T>> = Option::deserialize(d)?;
    Ok(v.unwrap_or_default())
}

pub fn null_to_map<'de, D, K, V>(d: D) -> Result<std::collections::HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: std::hash::Hash + Eq + Deserialize<'de>,
    V: Deserialize<'de>,
{
    let v: Option<std::collections::HashMap<K, V>> = Option::deserialize(d)?;
    Ok(v.unwrap_or_default())
}

/// Deserialize a query-string boolean that may be "1", "0", "true", "false"
/// or absent (None when absent, so callers can apply docker defaults).
pub fn flexible_bool<'de, D>(d: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(d)?;
    match s.as_deref() {
        None => Ok(None),
        Some("1") | Some("true") | Some("True") | Some("") => Ok(Some(true)),
        Some("0") | Some("false") | Some("False") => Ok(Some(false)),
        Some(other) => Err(serde::de::Error::custom(format!(
            "provided string was not `true` or `false`: {other}"
        ))),
    }
}

/// Deserialize a query parameter that may be a single value or repeated
/// (`t=a&t=b`) into a Vec<String>.
pub fn string_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVecVisitor;
    impl<'de> serde::de::Visitor<'de> for StringVecVisitor {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("string or sequence of strings")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }
    d.deserialize_any(StringVecVisitor)
}
