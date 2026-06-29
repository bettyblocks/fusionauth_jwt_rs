//! WASI-compatible verification of FusionAuth-issued JWTs.
//!
//! This is a Rust port of the JWKS verification strategy from the Elixir
//! [`fusion_jwt_authentication`] library, targeting `wasm32-wasip2` components
//! (e.g. for wasmCloud).
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
//! ```no_run
//! use fusionauth_jwt_rs::{Validation, Verifier};
//!
//! let validation = Validation::new()
//!     .issuer("bettyblocks.com")
//!     .audience("11111111-1111-1111-1111-111111111111");
//! let mut verifier = Verifier::new("https://auth.example.com", validation);
//!
//! # #[cfg(target_arch = "wasm32")]
//! # fn run(verifier: &mut Verifier, jwt: &str) -> Result<(), fusionauth_jwt_rs::Error> {
//! let claims = verifier.verify_token(jwt)?; // fetches JWKS via wasi:http
//! println!("subject: {:?}", claims.sub);
//! # Ok(())
//! # }
//! ```
//!
//! [`fusion_jwt_authentication`]: https://github.com/bettyblocks/fusion_jwt_authentication

mod crypto;
mod error;
mod jwks;
mod token;
mod validation;

#[cfg(target_arch = "wasm32")]
mod http;

pub use error::Error;
pub use jwks::{Jwk, Jwks};
pub use token::{Audience, Claims, Header, Jwt};
pub use validation::{Validation, validate_claims};

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
        let jwt = Jwt::parse(token)?;
        self.verify_parsed(jwt, jwks, now)
    }

    /// Replace the cached JWKS (e.g. with one you fetched yourself).
    pub fn set_jwks(&mut self, jwks: Jwks) {
        self.cache = Some(jwks);
    }

    /// Shared verification core, operating on an already-parsed token.
    fn verify_parsed(&self, jwt: Jwt, jwks: &Jwks, now: i64) -> Result<Claims, Error> {
        let kid = jwt.header.kid.as_deref().ok_or(Error::MissingKid)?;
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| Error::KidNotFound(kid.to_string()))?;

        // Guard against algorithm confusion: if the JWK pins an algorithm, the
        // header must agree with it.
        if let Some(jwk_alg) = &jwk.alg
            && jwk_alg != &jwt.header.alg
        {
            return Err(Error::UnsupportedAlgorithm(jwt.header.alg.clone()));
        }

        let key = jwk.to_rsa_public_key()?;
        crypto::verify_signature(&jwt.header.alg, &key, &jwt.signing_input, &jwt.signature)?;
        validate_claims(&jwt.claims, &self.validation, now)?;

        Ok(jwt.claims)
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
        let jwt = Jwt::parse(token)?;
        let kid = jwt.header.kid.as_deref().ok_or(Error::MissingKid)?;

        // Populate the cache on first use.
        if self.cache.is_none() {
            self.cache = Some(http::fetch_jwks(&self.base_url)?);
        }
        // Refetch once on an unknown kid, in case of key rotation.
        if self
            .cache
            .as_ref()
            .is_none_or(|jwks| jwks.find(kid).is_none())
        {
            self.cache = Some(http::fetch_jwks(&self.base_url)?);
        }

        let now = now_unix();
        // `cache` is guaranteed populated above.
        let jwks = self.cache.as_ref().expect("jwks cache populated");
        self.verify_parsed(jwt, jwks, now)
    }

    /// Force a JWKS refetch on the next [`Verifier::verify_token`] call.
    pub fn invalidate_cache(&mut self) {
        self.cache = None;
    }
}

/// Current wall-clock time in unix seconds, via `wasi:clocks` (through `std`).
#[cfg(target_arch = "wasm32")]
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
