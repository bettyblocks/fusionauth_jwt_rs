//! JWKS fetching from `<base_url>/.well-known/jwks.json`.
//!
//! Each backend exposes `fetch_jwks(base_url) -> Result<Jwks, Error>`. Native is
//! the default; the wasm backends are selected by feature:
//!
//! - **native** (non-wasm, default): blocking [`ureq`] client.
//! - **`wasip2`** (`wasm32-wasip2`): `wasi:http/outgoing-handler@0.2` via the
//!   [`wasi`](https://docs.rs/wasi) crate.
//! - **`wasip3`** (`wasm32-wasip3`): `wasi:http` 0.3 via [`wasi-fetch`]. See the
//!   module for caveats — this path is not yet build-verified.
//!
//! [`ureq`]: https://docs.rs/ureq
//! [`wasi-fetch`]: https://docs.rs/wasi-fetch

#[cfg(all(feature = "wasip2", feature = "wasip3"))]
compile_error!("features `wasip2` and `wasip3` are mutually exclusive — enable only one");

/// Path of the JWKS document, relative to the FusionAuth base URL.
pub(crate) const JWKS_PATH: &str = "/.well-known/jwks.json";

// Native (non-wasm): the `ureq` backend is always available — no feature needed.
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::fetch_jwks;

// wasm with no backend feature: fail with a clear message. The stub keeps
// `fetch_jwks` resolved so the only error reported is the one below.
#[cfg(all(target_arch = "wasm32", not(any(feature = "wasip2", feature = "wasip3"))))]
compile_error!("on wasm, enable a JWKS-fetch backend feature: `wasip2` or `wasip3`");
#[cfg(all(target_arch = "wasm32", not(any(feature = "wasip2", feature = "wasip3"))))]
pub(crate) fn fetch_jwks(_base_url: &str) -> Result<crate::jwks::Jwks, crate::error::Error> {
    unreachable!()
}

#[cfg(all(target_arch = "wasm32", feature = "wasip2"))]
mod wasip2;
#[cfg(all(target_arch = "wasm32", feature = "wasip2"))]
pub(crate) use wasip2::fetch_jwks;

// `not(feature = "wasip2")` keeps a single `fetch_jwks` in scope when both
// features are (mis)enabled, so the `compile_error!` above is the only error.
#[cfg(all(target_arch = "wasm32", feature = "wasip3", not(feature = "wasip2")))]
mod wasip3;
#[cfg(all(target_arch = "wasm32", feature = "wasip3", not(feature = "wasip2")))]
pub(crate) use wasip3::fetch_jwks;
