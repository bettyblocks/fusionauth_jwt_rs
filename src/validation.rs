//! Claim validation policy, translated onto `jsonwebtoken`'s [`Validation`].
//! `jsonwebtoken` performs all of the registered-claim checks
//! (`iss`/`aud`/`exp`/`nbf`) against the system clock. Mirrors the `iss`/`aud`/
//! `exp` options used by the Elixir `fusion_jwt_authentication` library.
//!
//! [`Validation`]: jsonwebtoken::Validation

use jsonwebtoken::{Algorithm, Validation as JwtValidation};

/// Which claims to enforce and how. Build with [`Validation::new`] and the
/// chained setters.
#[derive(Debug, Clone, Default)]
pub struct Validation {
    /// Required issuer (`iss`). `None` skips the check.
    pub issuer: Option<String>,
    /// Required audience (`aud`). `None` skips the check.
    pub audience: Option<String>,
    /// Clock-skew tolerance, in seconds, applied to `exp`/`nbf`.
    pub leeway: i64,
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

    /// Build the `jsonwebtoken` validation for this policy and signing
    /// algorithm. `jsonwebtoken` checks the signature, algorithm, `exp`/`nbf`,
    /// and (when configured) `iss`/`aud`.
    pub(crate) fn to_jwt_validation(&self, alg: Algorithm) -> JwtValidation {
        let mut v = JwtValidation::new(alg);
        v.leeway = self.leeway.max(0) as u64;

        // `exp` is always required; require `iss`/`aud` too when constrained, so
        // a token that simply omits an expected claim is rejected.
        let mut required = vec!["exp".to_string()];

        if let Some(iss) = &self.issuer {
            v.set_issuer(&[iss]);
            required.push("iss".to_string());
        }

        if let Some(aud) = &self.audience {
            v.set_audience(&[aud]);
            required.push("aud".to_string());
        } else {
            // Without an expected audience, don't reject tokens that carry one
            // (FusionAuth always sets `aud`).
            v.validate_aud = false;
        }

        v.set_required_spec_claims(&required);
        v
    }
}
