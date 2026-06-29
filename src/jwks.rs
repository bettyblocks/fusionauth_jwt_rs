//! JSON Web Key Set handling, as served by FusionAuth's
//! `/.well-known/jwks.json` endpoint.

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

use crate::error::Error;

/// A single JSON Web Key. Only the fields needed for RSA verification are
/// modelled; unknown fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key id, matched against the token header's `kid`.
    #[serde(default)]
    pub kid: Option<String>,
    /// Key type. Must be `"RSA"`.
    pub kty: String,
    /// Intended algorithm, e.g. `"RS256"`. When present it pins verification to
    /// that algorithm regardless of the token header.
    #[serde(default)]
    pub alg: Option<String>,
    /// Modulus, base64url-encoded.
    #[serde(default)]
    pub n: Option<String>,
    /// Public exponent, base64url-encoded.
    #[serde(default)]
    pub e: Option<String>,
}

impl Jwk {
    /// Build a [`DecodingKey`] and its pinned [`Algorithm`] from the JWK.
    ///
    /// The algorithm is taken from the JWK's `alg` when present (pinning it),
    /// otherwise from `header_alg`. Pinning is what blocks algorithm confusion:
    /// a key advertised as `RS256` only ever verifies `RS256` tokens.
    pub(crate) fn to_decoding_key(&self, header_alg: &str) -> Result<(DecodingKey, Algorithm), Error> {
        if self.kty != "RSA" {
            return Err(Error::InvalidKey);
        }
        let n = self.n.as_deref().ok_or(Error::InvalidKey)?;
        let e = self.e.as_deref().ok_or(Error::InvalidKey)?;

        let alg = match self.alg.as_deref().unwrap_or(header_alg) {
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            other => return Err(Error::UnsupportedAlgorithm(other.to_string())),
        };

        // `from_rsa_components` takes the base64url `n`/`e` strings as-is.
        let key = DecodingKey::from_rsa_components(n, e).map_err(|_| Error::InvalidKey)?;
        Ok((key, alg))
    }
}

/// A set of JSON Web Keys.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parse a JWKS document (the body of `/.well-known/jwks.json`).
    pub fn from_json(bytes: &[u8]) -> Result<Jwks, Error> {
        serde_json::from_slice(bytes).map_err(Error::InvalidJson)
    }

    /// Find the key with the given `kid`, if present.
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}