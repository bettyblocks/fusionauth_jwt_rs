//! JSON Web Key Set handling, as served by FusionAuth's
//! `/.well-known/jwks.json` endpoint.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{BigUint, RsaPublicKey};
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
    /// Intended algorithm, e.g. `"RS256"`. Used to reject algorithm confusion.
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
    /// Build an [`RsaPublicKey`] from the JWK's `n`/`e` parameters.
    pub fn to_rsa_public_key(&self) -> Result<RsaPublicKey, Error> {
        if self.kty != "RSA" {
            return Err(Error::InvalidKey);
        }
        let n = self.n.as_deref().ok_or(Error::InvalidKey)?;
        let e = self.e.as_deref().ok_or(Error::InvalidKey)?;

        let n = URL_SAFE_NO_PAD.decode(n).map_err(|_| Error::InvalidKey)?;
        let e = URL_SAFE_NO_PAD.decode(e).map_err(|_| Error::InvalidKey)?;

        RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
            .map_err(|_| Error::InvalidKey)
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
