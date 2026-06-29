//! Claim validation policy, translated onto `jwt-simple`'s
//! [`VerificationOptions`]. Mirrors the `iss`/`aud`/`exp` options used by the
//! Elixir `fusion_jwt_authentication` library.

use std::collections::HashSet;

use jwt_simple::prelude::{Duration, UnixTimeStamp, VerificationOptions};

/// Which claims to enforce and how. Build with [`Validation::new`] and the
/// chained setters.
#[derive(Debug, Clone)]
pub struct Validation {
    /// Required issuer (`iss`). `None` skips the check.
    pub issuer: Option<String>,
    /// Required audience (`aud`). `None` skips the check.
    pub audience: Option<String>,
    /// Clock-skew tolerance, in seconds, applied to `exp`/`nbf`.
    pub leeway: i64,
}

impl Default for Validation {
    fn default() -> Self {
        Validation {
            issuer: None,
            audience: None,
            leeway: 0,
        }
    }
}

impl Validation {
    /// Default validation: enforce expiry, no issuer/audience constraint.
    pub fn new() -> Self {
        Validation::default()
    }

    /// Require this issuer (`iss`).
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.issuer = Some(iss.into());
        self
    }

    /// Require this audience (`aud`). For FusionAuth this is the application id.
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    /// Allow this much clock skew (seconds) on `exp`/`nbf`.
    pub fn leeway(mut self, seconds: i64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Build the `jwt-simple` options for this policy.
    ///
    /// `now` injects the current time (unix seconds) for deterministic
    /// verification; pass `None` to use the real clock (`wasi:clocks` on wasm).
    pub(crate) fn to_options(&self, now: Option<i64>) -> VerificationOptions {
        VerificationOptions {
            allowed_issuers: self
                .issuer
                .as_ref()
                .map(|iss| HashSet::from([iss.clone()])),
            allowed_audiences: self
                .audience
                .as_ref()
                .map(|aud| HashSet::from([aud.clone()])),
            accept_future: false,
            artificial_time: now.map(|t| UnixTimeStamp::from_secs(t.max(0) as u64)),
            time_tolerance: Some(Duration::from_secs(self.leeway.max(0) as u64)),
            ..Default::default()
        }
    }
}
