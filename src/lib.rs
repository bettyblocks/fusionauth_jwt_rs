//! WASI-compatible verification of FusionAuth-issued JWTs.
//!
//! This is a Rust port of the JWKS verification strategy from the Elixir
//! [`fusion_jwt_authentication`] library, targeting `wasm32-wasip2` components
//! (e.g. for wasmCloud).
//!
//! Verification (signature, algorithm and the `iss`/`aud`/`exp`/`nbf` claims) is
//! delegated to [`jsonwebtoken`], built with its `rust_crypto` backend so the
//! RSA crypto is pure Rust and links cleanly into a `wasm32-wasip2` component.
//! This crate adds the FusionAuth-shaped pieces around it: JWKS fetching over
//! `wasi:http`, `kid` matching with refetch-on-rotation, and a typed [`Claims`]
//! view that preserves custom claims.
//!
//! # Two ways to use it
//!
//! 1. **Self-contained** ([`Verifier::verify_token`]): fetches the JWKS from
//!    FusionAuth, caches it, matches the token's `kid`, verifies the RS256
//!    signature and validates the claims. Like the Elixir `JWKS_Strategy`, it
//!    refetches the JWKS once if a `kid` is unknown. The transport is `wasi:http`
//!    on wasm (`wasip2`/`wasip3` feature) or a blocking `ureq` client on native.
//!
//! 2. **Bring-your-own-keys** ([`Verifier::verify_with_jwks`], all targets):
//!    you supply the [`Jwks`]. No I/O, so it runs and tests anywhere. Use this
//!    if you fetch/cache the JWKS yourself. `exp`/`nbf` are checked against the
//!    system clock.
//!
//! [`fusion_jwt_authentication`]: https://github.com/bettyblocks/fusion_jwt_authentication

mod error;
mod jwks;
mod token;
mod validation;

// The JWKS-fetch backend is opt-in via a feature matching the build target.
mod http;

use jsonwebtoken::errors::ErrorKind;

pub use error::Error;
pub use jwks::{Jwk, Jwks};
pub use token::{Audience, Claims};
pub use validation::Validation;

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

    /// Verify a token against a caller-supplied [`Jwks`]. Does no I/O, so it
    /// works on every target and is the entry point exercised by the test
    /// suite. `exp`/`nbf` are checked against the system clock (`wasi:clocks`
    /// on wasm).
    pub fn verify_with_jwks(&self, token: &str, jwks: &Jwks) -> Result<Claims, Error> {
        self.verify_core(token, jwks)
    }

    /// Replace the cached JWKS (e.g. with one you fetched yourself).
    pub fn set_jwks(&mut self, jwks: Jwks) {
        self.cache = Some(jwks);
    }

    /// Shared verification core: select the key by `kid`, then let
    /// `jsonwebtoken` verify the signature, algorithm and registered claims.
    fn verify_core(&self, token: &str, jwks: &Jwks) -> Result<Claims, Error> {
        // Peek at the (unverified) header to select the key.
        let header = jsonwebtoken::decode_header(token).map_err(|_| Error::MalformedToken)?;
        let header_alg = format!("{:?}", header.alg);
        let kid = header.kid.as_deref().ok_or(Error::MissingKid)?;

        let jwk = jwks
            .find(kid)
            .ok_or_else(|| Error::KidNotFound(kid.to_string()))?;

        // The algorithm is pinned by the JWK, so a token header cannot swap it:
        // `decode` rejects a header `alg` outside the pinned set.
        let (key, alg) = jwk.to_decoding_key(&header_alg)?;
        let options = self.validation.to_jwt_validation(alg);

        // `jsonwebtoken` verifies the signature, algorithm and `iss`/`aud`/
        // `exp`/`nbf` in one pass.
        let data = jsonwebtoken::decode::<Claims>(token, &key, &options)
            .map_err(|e| map_jwt_error(e, &header_alg))?;
        Ok(data.claims)
    }
}

impl Verifier {
    /// Verify a token end to end: fetch (and cache) the JWKS, match the `kid`,
    /// verify the signature and validate the claims.
    ///
    /// The JWKS is fetched over the per-target backend: `wasi:http` on wasm
    /// (`wasip2`/`wasip3` feature), or a blocking `ureq` client on native.
    ///
    /// Mirrors the Elixir `JWKS_Strategy`: if the token's `kid` is not in the
    /// cached set, the JWKS is refetched once (keys may have rotated) before
    /// giving up with [`Error::KidNotFound`].
    pub fn verify_token(&mut self, token: &str) -> Result<Claims, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| Error::MalformedToken)?;
        let kid = header.kid.ok_or(Error::MissingKid)?;

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

        // `cache` is guaranteed populated above.
        let jwks = self.cache.as_ref().expect("jwks cache populated");
        self.verify_core(token, jwks)
    }

    /// Force a JWKS refetch on the next [`Verifier::verify_token`] call.
    pub fn invalidate_cache(&mut self) {
        self.cache = None;
    }
}

/// Map a `jsonwebtoken` verification failure onto this crate's [`Error`].
/// Unrecognised failures fail closed as [`Error::InvalidSignature`].
fn map_jwt_error(err: jsonwebtoken::errors::Error, header_alg: &str) -> Error {
    match err.kind() {
        ErrorKind::InvalidSignature => Error::InvalidSignature,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            Error::UnsupportedAlgorithm(header_alg.to_string())
        }
        ErrorKind::InvalidRsaKey(_) | ErrorKind::InvalidKeyFormat => Error::InvalidKey,
        ErrorKind::ExpiredSignature => Error::TokenExpired,
        ErrorKind::ImmatureSignature => Error::TokenNotYetValid,
        ErrorKind::InvalidIssuer => Error::InvalidIssuer,
        ErrorKind::InvalidAudience => Error::InvalidAudience,
        // A required claim was absent: `iss`/`aud` map to the matching policy
        // error, `exp` (and the rest) to a missing-claim error.
        ErrorKind::MissingRequiredClaim(name) => match name.as_str() {
            "iss" => Error::InvalidIssuer,
            "aud" => Error::InvalidAudience,
            "exp" => Error::MissingClaim("exp"),
            "nbf" => Error::MissingClaim("nbf"),
            _ => Error::MalformedToken,
        },
        ErrorKind::InvalidClaimFormat(_)
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_)
        | ErrorKind::InvalidToken => Error::MalformedToken,
        _ => Error::InvalidSignature,
    }
}
