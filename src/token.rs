//! The claim types returned to callers.
//!
//! Parsing and signature verification are handled by [`jsonwebtoken`]; this
//! module defines the public, FusionAuth-shaped view of a token's claims,
//! deserialized straight out of the verified payload.

use serde::Deserialize;
use serde_json::Value;

/// The `aud` claim, which may be a single string or an array of strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// True if `aud` equals (single) or contains (array) the given value.
    pub fn contains(&self, aud: &str) -> bool {
        match self {
            Audience::Single(s) => s == aud,
            Audience::Multiple(v) => v.iter().any(|s| s == aud),
        }
    }
}

/// The decoded claim set of a verified token. Registered claims are typed;
/// everything else (FusionAuth custom claims such as `cas_token`, roles, etc.)
/// is preserved in [`Claims::extra`] and reachable via [`Claims::get`].
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Claims {
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub aud: Option<Audience>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    /// Any non-registered claims carried by the token.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl Claims {
    /// Look up a non-registered claim by name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.extra.get(key)
    }
}