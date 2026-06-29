//! Claim validation, mirroring Joken's `default_claims` with the `iss`/`aud`
//! options used by the Elixir `fusion_jwt_authentication` library.

use crate::error::Error;
use crate::token::Claims;

/// Which claims to enforce and how. Build with [`Validation::new`] and the
/// chained setters.
#[derive(Debug, Clone)]
pub struct Validation {
    /// Required issuer (`iss`). `None` skips the check.
    pub issuer: Option<String>,
    /// Required audience (`aud`). `None` skips the check.
    pub audience: Option<String>,
    /// Enforce `exp` (expiry).
    pub validate_exp: bool,
    /// Enforce `nbf` (not-before) when the claim is present.
    pub validate_nbf: bool,
    /// Reject tokens that carry no `exp` at all.
    pub require_exp: bool,
    /// Clock-skew tolerance, in seconds.
    pub leeway: i64,
}

impl Default for Validation {
    fn default() -> Self {
        Validation {
            issuer: None,
            audience: None,
            validate_exp: true,
            validate_nbf: true,
            require_exp: true,
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
}

/// Validate the registered claims against `validation`, treating `now` as the
/// current time (unix seconds).
pub fn validate_claims(claims: &Claims, validation: &Validation, now: i64) -> Result<(), Error> {
    if let Some(expected) = &validation.issuer {
        match &claims.iss {
            Some(iss) if iss == expected => {}
            _ => return Err(Error::InvalidIssuer),
        }
    }

    if let Some(expected) = &validation.audience {
        match &claims.aud {
            Some(aud) if aud.contains(expected) => {}
            _ => return Err(Error::InvalidAudience),
        }
    }

    if validation.validate_exp {
        match claims.exp {
            // Expired once now has advanced past exp + leeway.
            Some(exp) if now - validation.leeway >= exp => return Err(Error::TokenExpired),
            Some(_) => {}
            None if validation.require_exp => return Err(Error::MissingClaim("exp")),
            None => {}
        }
    }

    if validation.validate_nbf
        && let Some(nbf) = claims.nbf
        && now + validation.leeway < nbf
    {
        return Err(Error::TokenNotYetValid);
    }

    Ok(())
}
