//! Typed parameter accessors. Wrong types are errors, never panics.

use std::str::FromStr;

use serde_json::Value;

use crate::{EngineError, Result};

pub fn opt_str<'a>(p: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(EngineError::bad(key, "must be a string")),
    }
}

pub fn req_str<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    opt_str(p, key)?.ok_or_else(|| EngineError::bad(key, "is required"))
}

pub fn opt_bool(p: &Value, key: &str) -> Result<Option<bool>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(EngineError::bad(key, "must be true or false")),
    }
}

pub fn opt_u32(p: &Value, key: &str) -> Result<Option<u32>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "must be an integer 0..=4294967295")),
    }
}

pub fn req_u32(p: &Value, key: &str) -> Result<u32> {
    opt_u32(p, key)?.ok_or_else(|| EngineError::bad(key, "is required"))
}

/// Optional string parsed with `FromStr` (interface names, prefixes, ids...).
pub fn opt_parse<T>(p: &Value, key: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    opt_str(p, key)?
        .map(|s| {
            s.parse::<T>()
                .map_err(|e| EngineError::bad(key, e.to_string()))
        })
        .transpose()
}

pub fn req_parse<T>(p: &Value, key: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    opt_parse(p, key)?.ok_or_else(|| EngineError::bad(key, "is required"))
}

/// Free text (comments, identity): bounded and without control characters.
pub fn opt_text(p: &Value, key: &str, max: usize) -> Result<Option<String>> {
    let Some(s) = opt_str(p, key)? else {
        return Ok(None);
    };
    if s.chars().count() > max {
        return Err(EngineError::bad(key, format!("at most {max} characters")));
    }
    if s.chars().any(char::is_control) {
        return Err(EngineError::bad(key, "control characters are not allowed"));
    }
    Ok(Some(s.to_owned()))
}
