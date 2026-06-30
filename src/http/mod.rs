//! JWKS fetching from `<base_url>/.well-known/jwks.json`.
//!
//! Each backend exposes `fetch_jwks(base_url) -> Result<Jwks, Error>` and is
//! selected by feature:
//!
//! - **`native-http`** (non-wasm): blocking [`ureq`] client.
//! - **`wasip2`** (`wasm32-wasip2`): `wasi:http/outgoing-handler@0.2` via the
//!   [`wasi`](https://docs.rs/wasi) crate.
//! - **`wasip3`** (`wasm32-wasip3`): `wasi:http` 0.3 via [`wasi-fetch`]. See the
//!   module for caveats — this path is not yet build-verified.
//!
//! This module is only compiled when one of those features is active for the
//! current target (see the gating on `mod http` in the crate root).
//!
//! [`ureq`]: https://docs.rs/ureq
//! [`wasi-fetch`]: https://docs.rs/wasi-fetch

#[cfg(all(feature = "wasip2", feature = "wasip3"))]
compile_error!("features `wasip2` and `wasip3` are mutually exclusive — enable only one");

/// Path of the JWKS document, relative to the FusionAuth base URL.
pub(crate) const JWKS_PATH: &str = "/.well-known/jwks.json";

#[cfg(all(not(target_arch = "wasm32"), feature = "native-http"))]
mod native;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-http"))]
pub(crate) use native::fetch_jwks;

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
