use std::fmt;

/// Everything that can go wrong while verifying a FusionAuth JWT.
#[derive(Debug)]
pub enum Error {
    /// The token is not a well-formed `header.payload.signature` string.
    MalformedToken,
    /// A token segment was not valid base64url.
    InvalidBase64,
    /// A token segment or the JWKS response was not valid JSON.
    InvalidJson(serde_json::Error),
    /// The token header had no `kid`. FusionAuth always sets one.
    MissingKid,
    /// No JWK in the set matched the token's `kid`.
    KidNotFound(String),
    /// The signing algorithm is not a supported RSA variant, or the header
    /// algorithm disagrees with the JWK's declared algorithm.
    UnsupportedAlgorithm(String),
    /// The JWK could not be turned into an RSA public key.
    InvalidKey,
    /// The RSA signature did not verify against the matched key.
    InvalidSignature,
    /// `exp` is in the past (accounting for leeway).
    TokenExpired,
    /// `nbf` is in the future (accounting for leeway).
    TokenNotYetValid,
    /// `iss` did not match the configured issuer.
    InvalidIssuer,
    /// `aud` did not contain the configured audience.
    InvalidAudience,
    /// A claim required by the configured validation was absent.
    MissingClaim(&'static str),
    /// Fetching the JWKS over `wasi:http` failed.
    Http(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedToken => write!(f, "malformed token"),
            Error::InvalidBase64 => write!(f, "invalid base64url in token"),
            Error::InvalidJson(e) => write!(f, "invalid json: {e}"),
            Error::MissingKid => write!(f, "no kid in token header"),
            Error::KidNotFound(kid) => write!(f, "kid does not match any jwk: {kid}"),
            Error::UnsupportedAlgorithm(alg) => write!(f, "unsupported algorithm: {alg}"),
            Error::InvalidKey => write!(f, "invalid rsa key in jwks"),
            Error::InvalidSignature => write!(f, "signature verification failed"),
            Error::TokenExpired => write!(f, "token has expired"),
            Error::TokenNotYetValid => write!(f, "token is not yet valid"),
            Error::InvalidIssuer => write!(f, "issuer does not match"),
            Error::InvalidAudience => write!(f, "audience does not match"),
            Error::MissingClaim(c) => write!(f, "missing required claim: {c}"),
            Error::Http(msg) => write!(f, "jwks http request failed: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InvalidJson(e) => Some(e),
            _ => None,
        }
    }
}
