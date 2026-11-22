//! Lenient typed reading of the daemons' JSON (G3.4n).
//!
//! The state readers used to parse each answer into a `serde_json::Value`
//! tree and pick the fields from it: every key and every string of the
//! answer allocated, then freed, every poll. These wrappers let a reader
//! name only the fields it keeps (a `#[derive(Deserialize)]` struct); the
//! rest is skipped as it is read (`IgnoredAny`), and strings without
//! escapes are borrowed from the buffer. Numbers in `docs/ospf.md`.
//!
//! The leniency of the old readers is kept: a field of an unexpected type
//! is `None` ([`Loose`]), an entry that is not an object is skipped
//! ([`Obj`]), a list or map of the wrong shape is empty ([`List`],
//! [`Dict`]). Only JSON that is not JSON is an error.

use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

/// A scalar field of any type.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Loose<'a> {
    U(u64),
    I(i64),
    F(f64),
    S(Cow<'a, str>),
    B(bool),
    /// null, an object or a list.
    #[default]
    Other,
}

impl Loose<'_> {
    /// A non-negative integer, or a string holding one (FRR prints some
    /// counters as strings).
    pub fn u64(&self) -> Option<u64> {
        match self {
            Loose::U(n) => Some(*n),
            Loose::I(n) => u64::try_from(*n).ok(),
            Loose::S(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn u32(&self) -> Option<u32> {
        self.u64().and_then(|n| u32::try_from(n).ok())
    }

    /// The text, when it is a string.
    pub fn str(&self) -> Option<&str> {
        match self {
            Loose::S(s) => Some(s),
            _ => None,
        }
    }

    /// A non-empty string, cut to 128 characters (the daemon's text is not
    /// trusted to be short).
    pub fn text(&self) -> Option<String> {
        self.str().filter(|s| !s.is_empty()).map(|s| {
            // At most 128 bytes is at most 128 characters: one copy.
            if s.len() <= 128 {
                s.to_owned()
            } else {
                s.chars().take(128).collect()
            }
        })
    }

    pub fn bool(&self) -> Option<bool> {
        match self {
            Loose::B(b) => Some(*b),
            _ => None,
        }
    }
}

/// `Option<Loose>` helpers, for `#[serde(default)]` fields.
pub fn text(v: &Option<Loose<'_>>) -> Option<String> {
    v.as_ref().and_then(Loose::text)
}

pub fn u64_of(v: &Option<Loose<'_>>) -> Option<u64> {
    v.as_ref().and_then(Loose::u64)
}

pub fn u32_of(v: &Option<Loose<'_>>) -> Option<u32> {
    v.as_ref().and_then(Loose::u32)
}

pub fn bool_of(v: &Option<Loose<'_>>) -> Option<bool> {
    v.as_ref().and_then(Loose::bool)
}

fn drain_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
    while seq.next_element::<IgnoredAny>()?.is_some() {}
    Ok(())
}

fn drain_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
    Ok(())
}

/// The scalar visitors every wrapper shares: anything that is not the
/// expected container is `default()`.
macro_rules! scalars_are_default {
    () => {
        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
    };
}

impl<'de: 'a, 'a> Deserialize<'de> for Loose<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Loose<'a>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Loose<'a>, E> {
                Ok(Loose::B(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Loose<'a>, E> {
                Ok(Loose::I(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Loose<'a>, E> {
                Ok(Loose::U(v))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Loose<'a>, E> {
                Ok(Loose::F(v))
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Loose<'a>, E> {
                Ok(Loose::S(Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Loose<'a>, E> {
                Ok(Loose::S(Cow::Owned(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Loose<'a>, E> {
                Ok(Loose::S(Cow::Owned(v)))
            }
            fn visit_unit<E>(self) -> Result<Loose<'a>, E> {
                Ok(Loose::Other)
            }
            fn visit_none<E>(self) -> Result<Loose<'a>, E> {
                Ok(Loose::Other)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Loose<'a>, A::Error> {
                drain_seq(seq).map(|()| Loose::Other)
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Loose<'a>, A::Error> {
                drain_map(map).map(|()| Loose::Other)
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// An object read as `T`; anything else is `None`.
#[derive(Debug)]
pub struct Obj<T>(pub Option<T>);

impl<T> Default for Obj<T> {
    fn default() -> Self {
        Obj(None)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Obj<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = Obj<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            scalars_are_default!();
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Obj<T>, A::Error> {
                drain_seq(seq).map(|()| Obj(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Obj<T>, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(|t| Obj(Some(t)))
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// A list of objects (`T` each; other elements are skipped); anything
/// else is empty. At most `MAX` kept, the rest read and dropped.
#[derive(Debug)]
pub struct List<T, const MAX: usize = { usize::MAX }>(pub Vec<T>);

impl<T, const MAX: usize> Default for List<T, MAX> {
    fn default() -> Self {
        List(Vec::new())
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for List<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for V<T, MAX> {
            type Value = List<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list")
            }
            scalars_are_default!();
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<List<T, MAX>, A::Error> {
                let mut out = Vec::new();
                while let Some(Obj(item)) = seq.next_element::<Obj<T>>()? {
                    if let Some(item) = item
                        && out.len() < MAX
                    {
                        out.push(item);
                    }
                }
                Ok(List(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<List<T, MAX>, A::Error> {
                drain_map(map).map(|()| List(Vec::new()))
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// An object read as (key, `T`) pairs in order (entries that are not
/// objects are skipped); anything else is empty.
#[derive(Debug)]
pub struct Dict<'a, T>(pub Vec<(Cow<'a, str>, T)>);

impl<T> Default for Dict<'_, T> {
    fn default() -> Self {
        Dict(Vec::new())
    }
}

impl<'de: 'a, 'a, T: Deserialize<'de>> Deserialize<'de> for Dict<'a, T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a, T>(PhantomData<(&'a (), T)>);
        impl<'de: 'a, 'a, T: Deserialize<'de>> Visitor<'de> for V<'a, T> {
            type Value = Dict<'a, T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            scalars_are_default!();
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Dict<'a, T>, A::Error> {
                drain_seq(seq).map(|()| Dict(Vec::new()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Dict<'a, T>, A::Error> {
                let mut out = Vec::new();
                while let Some(k) = map.next_key::<Cow<'a, str>>()? {
                    let v = map.next_value::<T>()?;
                    out.push((k, v));
                }
                Ok(Dict(out))
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// Parse `json` as `T`, with the daemon's name in the error.
pub fn parse<'a, T: Deserialize<'a>>(json: &'a [u8], daemon: &str) -> Result<T, String> {
    serde_json::from_slice(json).map_err(|e| format!("{daemon} answered bad JSON: {e}"))
}

/// Whether the answer is a JSON object (a daemon not running yet answers a
/// warning in text).
pub fn is_object(out: &[u8]) -> bool {
    out.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize, Default, Debug)]
    #[serde(default)]
    struct Row<'a> {
        #[serde(borrow)]
        name: Option<Loose<'a>>,
        n: Option<Loose<'a>>,
    }

    #[test]
    fn odd_shapes_are_empty_not_errors() {
        let d: Dict<'_, Obj<Row<'_>>> = parse(
            br#"{"a":{"name":"x","n":"7"},"b":5,"c":[1],"d":{"name":3,"n":{"k":1}}}"#,
            "t",
        )
        .unwrap();
        assert_eq!(d.0.len(), 4);
        let a = d.0[0].1.0.as_ref().unwrap();
        assert_eq!(
            (text(&a.name).as_deref(), u64_of(&a.n)),
            (Some("x"), Some(7))
        );
        assert!(d.0[1].1.0.is_none() && d.0[2].1.0.is_none());
        let dd = d.0[3].1.0.as_ref().unwrap();
        assert_eq!((text(&dd.name), u64_of(&dd.n)), (None, None));
        let l: List<Row<'_>, 2> = parse(br#"[{"n":1},7,{"n":2},{"n":3}]"#, "t").unwrap();
        assert_eq!(l.0.len(), 2);
        let l: List<Row<'_>> = parse(br#"{"x":1}"#, "t").unwrap();
        assert!(l.0.is_empty());
        assert!(
            parse::<Dict<'_, Obj<Row<'_>>>>(b"nope", "ospfd")
                .unwrap_err()
                .contains("ospfd")
        );
        // Escaped strings are copied, plain ones borrowed.
        let r: Row<'_> = parse(br#"{"name":"a\"b"}"#, "t").unwrap();
        assert_eq!(text(&r.name).as_deref(), Some("a\"b"));
        assert!(is_object(b"  \n{}") && !is_object(b"% not running"));
        // Long text is cut at 128 characters, never inside one.
        let long = Loose::S(Cow::Owned("é".repeat(100)));
        assert_eq!(long.text().map(|t| t.chars().count()), Some(100));
        let long = Loose::S(Cow::Owned("é".repeat(200)));
        assert_eq!(long.text().map(|t| t.chars().count()), Some(128));
        assert_eq!(Loose::S(Cow::Borrowed("")).text(), None);
    }
}
