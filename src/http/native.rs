//! JWKS fetching on native (non-wasm) targets via the blocking [`ureq`] client.
//! Compiled only when the `native-http` feature is enabled.
//!
//! [`ureq`]: https://docs.rs/ureq

use super::JWKS_PATH;
use crate::error::Error;
use crate::jwks::Jwks;

/// Fetch and parse the JWKS from `<base_url>/.well-known/jwks.json`.
pub(crate) fn fetch_jwks(base_url: &str) -> Result<Jwks, Error> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), JWKS_PATH);

    let mut response = ureq::get(&url)
        .call()
        .map_err(|e| Error::Http(format!("request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::Http(format!("unexpected status {}", status.as_u16())));
    }

    let bytes = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| Error::Http(format!("body read failed: {e}")))?;

    Jwks::from_json(&bytes)
}
