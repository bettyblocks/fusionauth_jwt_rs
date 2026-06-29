//! The claim types returned to callers.
//!
//! Parsing and signature verification are handled by [`jwt-simple`]; this module
//! only defines the public, FusionAuth-shaped view of a verified token's claims.
//!
//! [`jwt-simple`]: https://docs.rs/jwt-simple

use serde_json::Value;

/// The `aud` claim, which may be a single string or an array of strings.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Default)]
pub struct Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<Audience>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    /// Any non-registered claims carried by the token.
    pub extra: serde_json::Map<String, Value>,
}

impl Claims {
    /// Look up a non-registered claim by name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.extra.get(key)
    }
}