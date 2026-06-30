//! JWKS fetching from `<base_url>/.well-known/jwks.json`.
//!
//! Exactly one backend is compiled per target, each exposing
//! `fetch_jwks(base_url) -> Result<Jwks, Error>`:
//!
//! - **native** (non-wasm): blocking [`ureq`] client, behind the `native-http`
//!   feature.
//! - **wasip2** (`wasm32-wasip2`): `wasi:http/outgoing-handler@0.2` via the
//!   [`wasi`](https://docs.rs/wasi) crate.
//! - **wasip3** (`wasm32-wasip3`): `wasi:http` 0.3 via [`wasi-fetch`]. See the
//!   module for caveats — this path is not yet build-verified.
//!
//! [`ureq`]: https://docs.rs/ureq
//! [`wasi-fetch`]: https://docs.rs/wasi-fetch

/// Path of the JWKS document, relative to the FusionAuth base URL.
pub(crate) const JWKS_PATH: &str = "/.well-known/jwks.json";

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::fetch_jwks;

#[cfg(all(target_arch = "wasm32", target_env = "p2"))]
mod wasip2;
#[cfg(all(target_arch = "wasm32", target_env = "p2"))]
pub(crate) use wasip2::fetch_jwks;

#[cfg(all(target_arch = "wasm32", target_env = "p3"))]
mod wasip3;
#[cfg(all(target_arch = "wasm32", target_env = "p3"))]
pub(crate) use wasip3::fetch_jwks;
