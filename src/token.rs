//! JWT parsing: the `header.payload.signature` structure and its claims.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;

/// The decoded JOSE header of a JWT.
#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    /// Signing algorithm, e.g. `"RS256"`.
    pub alg: String,
    /// Key id, used to select the matching JWK. FusionAuth always sets this.
    #[serde(default)]
    pub kid: Option<String>,
    /// Token type, usually `"JWT"`.
    #[serde(default)]
    pub typ: Option<String>,
}

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

/// The decoded claim set. Registered claims are typed; everything else
/// (FusionAuth custom claims such as `cas_token`, roles, etc.) is preserved
/// in [`Claims::extra`] and reachable via [`Claims::get`].
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

/// A parsed (not-yet-verified) JWT.
///
/// Parsing only decodes the structure; it makes no trust decision. Call
/// [`crate::Verifier`] to check the signature and claims.
pub struct Jwt {
    pub header: Header,
    pub claims: Claims,
    /// The exact ASCII bytes that were signed: `base64url(header).base64url(payload)`.
    pub(crate) signing_input: String,
    /// The raw (base64url-decoded) signature bytes.
    pub(crate) signature: Vec<u8>,
}

fn b64_decode(input: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| Error::InvalidBase64)
}

impl Jwt {
    /// Split and decode a compact JWS. Does **not** verify the signature.
    pub fn parse(token: &str) -> Result<Jwt, Error> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(Error::MalformedToken)?;
        let payload_b64 = parts.next().ok_or(Error::MalformedToken)?;
        let signature_b64 = parts.next().ok_or(Error::MalformedToken)?;
        // A compact JWS has exactly three segments.
        if parts.next().is_some() {
            return Err(Error::MalformedToken);
        }

        let header: Header =
            serde_json::from_slice(&b64_decode(header_b64)?).map_err(Error::InvalidJson)?;
        let claims: Claims =
            serde_json::from_slice(&b64_decode(payload_b64)?).map_err(Error::InvalidJson)?;
        let signature = b64_decode(signature_b64)?;
        let signing_input = format!("{header_b64}.{payload_b64}");

        Ok(Jwt {
            header,
            claims,
            signing_input,
            signature,
        })
    }
}
