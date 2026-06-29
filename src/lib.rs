//! WASI-compatible verification of FusionAuth-issued JWTs.
//!
//! This is a Rust port of the JWKS verification strategy from the Elixir
//! [`fusion_jwt_authentication`] library, targeting `wasm32-wasip2` components
//! (e.g. for wasmCloud).
//!
//! Signature verification and claim checks are delegated to [`jwt-simple`],
//! which is pure Rust (no `ring`/C) and so links cleanly into a WASI component.
//! This crate adds the FusionAuth-shaped pieces around it: JWKS fetching over
//! `wasi:http`, `kid` matching with refetch-on-rotation, and a typed [`Claims`]
//! view that preserves custom claims.
//!
//! # Two ways to use it
//!
//! 1. **Self-contained** ([`Verifier::verify_token`], `wasm32` only): fetches
//!    the JWKS from FusionAuth over `wasi:http`, caches it, matches the token's
//!    `kid`, verifies the RS256 signature and validates the claims. Like the
//!    Elixir `JWKS_Strategy`, it refetches the JWKS once if a `kid` is unknown.
//!
//! 2. **Bring-your-own-keys** ([`Verifier::verify_with_jwks`], all targets):
//!    you supply the [`Jwks`] and current time. No I/O, so it runs and tests
//!    anywhere. Use this if you fetch/cache the JWKS yourself.
//!
//! [`fusion_jwt_authentication`]: https://github.com/bettyblocks/fusion_jwt_authentication
//! [`jwt-simple`]: https://docs.rs/jwt-simple

mod error;
mod jwks;
mod token;
mod validation;

#[cfg(target_arch = "wasm32")]
mod http;

use jwt_simple::prelude::{Audiences, JWTClaims, RSAPublicKeyLike, Token};
use jwt_simple::{Error as JwtError, JWTError};
use serde_json::Value;

pub use error::Error;
pub use jwks::{Jwk, Jwks};
pub use token::{Audience, Claims};
pub use validation::Validation;

use jwks::VerifyingKey;

/// The custom (non-registered) claims, captured verbatim so FusionAuth claims
/// such as `cas_token` survive verification.
type Extra = serde_json::Map<String, Value>;

/// Verifies FusionAuth JWTs against a JWKS.
///
/// Holds the FusionAuth base URL, the [`Validation`] policy, and (on `wasm32`)
/// a cached copy of the JWKS so repeated verifications avoid extra HTTP calls.
pub struct Verifier {
    /// FusionAuth base URL, e.g. `https://auth.example.com`.
    pub base_url: String,
    /// Claim validation policy.
    pub validation: Validation,
    /// Cached JWKS (populated by [`Verifier::verify_token`]).
    cache: Option<Jwks>,
}

impl Verifier {
    /// Create a verifier for the given FusionAuth base URL and validation policy.
    pub fn new(base_url: impl Into<String>, validation: Validation) -> Self {
        Verifier {
            base_url: base_url.into(),
            validation,
            cache: None,
        }
    }

    /// Verify a token against a caller-supplied [`Jwks`] at time `now` (unix
    /// seconds). Pure: no I/O and no clock access, so it works on every target
    /// and is the entry point exercised by the test suite.
    pub fn verify_with_jwks(&self, token: &str, jwks: &Jwks, now: i64) -> Result<Claims, Error> {
        self.verify_core(token, jwks, Some(now))
    }

    /// Replace the cached JWKS (e.g. with one you fetched yourself).
    pub fn set_jwks(&mut self, jwks: Jwks) {
        self.cache = Some(jwks);
    }

    /// Shared verification core. `now` injects the current time for the pure
    /// path; `None` lets `jwt-simple` use the real clock (`wasi:clocks`).
    fn verify_core(&self, token: &str, jwks: &Jwks, now: Option<i64>) -> Result<Claims, Error> {
        // Peek at the (unverified) header to select the key.
        let meta = Token::decode_metadata(token).map_err(|_| Error::MalformedToken)?;
        let kid = meta.key_id().ok_or(Error::MissingKid)?;
        let header_alg = meta.algorithm().to_string();

        let jwk = jwks
            .find(kid)
            .ok_or_else(|| Error::KidNotFound(kid.to_string()))?;

        // The key's algorithm is pinned here, so a token header cannot swap it.
        let key = jwk.to_verifying_key(&header_alg)?;
        let options = self.validation.to_options(now);

        // `jwt-simple` checks the signature, `iss`/`aud`, and `exp`/`nbf`.
        let verified: JWTClaims<Extra> = match &key {
            VerifyingKey::Rs256(k) => k.verify_token(token, Some(options)),
            VerifyingKey::Rs384(k) => k.verify_token(token, Some(options)),
            VerifyingKey::Rs512(k) => k.verify_token(token, Some(options)),
        }
        .map_err(|e| map_jwt_error(e, &header_alg))?;

        let claims = to_claims(verified);
        self.validation.check_extra(&claims)?;
        Ok(claims)
    }
}

#[cfg(target_arch = "wasm32")]
impl Verifier {
    /// Verify a token end to end: fetch (and cache) the JWKS over `wasi:http`,
    /// match the `kid`, verify the signature and validate the claims.
    ///
    /// Mirrors the Elixir `JWKS_Strategy`: if the token's `kid` is not in the
    /// cached set, the JWKS is refetched once (keys may have rotated) before
    /// giving up with [`Error::KidNotFound`].
    pub fn verify_token(&mut self, token: &str) -> Result<Claims, Error> {
        let meta = Token::decode_metadata(token).map_err(|_| Error::MalformedToken)?;
        let kid = meta.key_id().ok_or(Error::MissingKid)?.to_string();

        // Populate the cache on first use.
        if self.cache.is_none() {
            self.cache = Some(http::fetch_jwks(&self.base_url)?);
        }
        // Refetch once on an unknown kid, in case of key rotation.
        if self
            .cache
            .as_ref()
            .is_none_or(|jwks| jwks.find(&kid).is_none())
        {
            self.cache = Some(http::fetch_jwks(&self.base_url)?);
        }

        // `cache` is guaranteed populated above. `None` => use the real clock.
        let jwks = self.cache.as_ref().expect("jwks cache populated");
        self.verify_core(token, jwks, None)
    }

    /// Force a JWKS refetch on the next [`Verifier::verify_token`] call.
    pub fn invalidate_cache(&mut self) {
        self.cache = None;
    }
}

/// Map a `jwt-simple` verification failure onto this crate's [`Error`].
/// Unrecognised failures fail closed as [`Error::InvalidSignature`].
fn map_jwt_error(err: JwtError, header_alg: &str) -> Error {
    match err.downcast_ref::<JWTError>() {
        Some(JWTError::TokenHasExpired) => Error::TokenExpired,
        Some(JWTError::TokenNotValidYet) => Error::TokenNotYetValid,
        Some(JWTError::RequiredIssuerMismatch | JWTError::RequiredIssuerMissing) => {
            Error::InvalidIssuer
        }
        Some(JWTError::RequiredAudienceMismatch | JWTError::RequiredAudienceMissing) => {
            Error::InvalidAudience
        }
        Some(JWTError::AlgorithmMismatch) => Error::UnsupportedAlgorithm(header_alg.to_string()),
        Some(JWTError::CompactEncodingError | JWTError::NotJWT) => Error::MalformedToken,
        _ => Error::InvalidSignature,
    }
}

/// Map `jwt-simple`'s registered + custom claims onto this crate's [`Claims`].
fn to_claims(jc: JWTClaims<Extra>) -> Claims {
    Claims {
        iss: jc.issuer,
        sub: jc.subject,
        aud: jc.audiences.map(|a| match a {
            Audiences::AsString(s) => Audience::Single(s),
            Audiences::AsSet(set) => Audience::Multiple(set.into_iter().collect()),
        }),
        exp: jc.expires_at.map(|d| d.as_secs() as i64),
        nbf: jc.invalid_before.map(|d| d.as_secs() as i64),
        iat: jc.issued_at.map(|d| d.as_secs() as i64),
        extra: jc.custom,
    }
}