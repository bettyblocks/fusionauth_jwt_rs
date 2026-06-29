//! JSON Web Key Set handling, as served by FusionAuth's
//! `/.well-known/jwks.json` endpoint.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jwt_simple::prelude::{RS256PublicKey, RS384PublicKey, RS512PublicKey};

use crate::error::Error;

/// An RSA verifying key, with the digest variant pinned at construction so the
/// token header's `alg` cannot be substituted (algorithm-confusion guard).
pub(crate) enum VerifyingKey {
    Rs256(RS256PublicKey),
    Rs384(RS384PublicKey),
    Rs512(RS512PublicKey),
}

/// A single JSON Web Key. Only the fields needed for RSA verification are
/// modelled; unknown fields are ignored.
#[derive(Debug, Clone, serde::Deserialize)]
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
    /// Build a [`VerifyingKey`] from the JWK's `n`/`e` parameters.
    ///
    /// The algorithm is taken from the JWK's `alg` when present (pinning it),
    /// otherwise from `header_alg`. This is what blocks algorithm confusion: a
    /// key advertised as `RS256` only ever yields an `RS256` verifier.
    pub(crate) fn to_verifying_key(&self, header_alg: &str) -> Result<VerifyingKey, Error> {
        if self.kty != "RSA" {
            return Err(Error::InvalidKey);
        }
        let n = self.n.as_deref().ok_or(Error::InvalidKey)?;
        let e = self.e.as_deref().ok_or(Error::InvalidKey)?;
        let n = URL_SAFE_NO_PAD.decode(n).map_err(|_| Error::InvalidKey)?;
        let e = URL_SAFE_NO_PAD.decode(e).map_err(|_| Error::InvalidKey)?;

        let alg = self.alg.as_deref().unwrap_or(header_alg);
        let key = match alg {
            "RS256" => VerifyingKey::Rs256(
                RS256PublicKey::from_components(&n, &e).map_err(|_| Error::InvalidKey)?,
            ),
            "RS384" => VerifyingKey::Rs384(
                RS384PublicKey::from_components(&n, &e).map_err(|_| Error::InvalidKey)?,
            ),
            "RS512" => VerifyingKey::Rs512(
                RS512PublicKey::from_components(&n, &e).map_err(|_| Error::InvalidKey)?,
            ),
            other => return Err(Error::UnsupportedAlgorithm(other.to_string())),
        };
        Ok(key)
    }
}

/// A set of JSON Web Keys.
#[derive(Debug, Clone, serde::Deserialize)]
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