//! JWKS fetching over `wasi:http` 0.3 (`wasm32-wasip3`).
//!
//! WASI 0.3 makes I/O natively async, so this uses the [`wasi-fetch`] client
//! and bridges its async API back to our synchronous [`fetch_jwks`] with
//! [`block_on`]. `block_on` drives the future to completion on the component's
//! async runtime; it is intended for exactly this sync-over-async bridging.
//!
//! NOTE: at the time of writing there is no prebuilt `wasm32-wasip3` std for
//! stable Rust, so this backend is **not build-verified** here. It targets
//! `wasi-fetch` 0.2 / `wasip3` 0.7 (`wasi:http` 0.3.0). If you build a wasip3
//! component and the client/runtime API has moved, this module is the only
//! place that needs adjusting.
//!
//! [`wasi-fetch`]: https://docs.rs/wasi-fetch
//! [`block_on`]: wasip3::wit_bindgen::block_on

use wasip3::wit_bindgen::block_on;

use super::JWKS_PATH;
use crate::error::Error;
use crate::jwks::Jwks;

/// Fetch and parse the JWKS from `<base_url>/.well-known/jwks.json`.
pub(crate) fn fetch_jwks(base_url: &str) -> Result<Jwks, Error> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), JWKS_PATH);

    // wasip3 I/O is async; run it to completion on the component runtime.
    let bytes = block_on(async move {
        let response = wasi_fetch::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(format!("request failed: {e:?}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Http(format!("unexpected status {}", status.as_u16())));
        }

        let body = response.into_body().bytes().await;
        Ok::<Vec<u8>, Error>(body.to_vec())
    })?;

    Jwks::from_json(&bytes)
}
