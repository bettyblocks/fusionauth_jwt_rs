# fusionauth_jwt_rs

WASI-compatible verification of [FusionAuth](https://fusionauth.io)-issued JWTs,
for [wasmCloud](https://wasmcloud.com) components.

This is a Rust port of the **JWKS verification strategy** from the Elixir
[`fusion_jwt_authentication`](https://github.com/bettyblocks/fusion_jwt_authentication)
library. It verifies RS256 (and RS384/RS512) tokens signed by FusionAuth by:

1. matching the token's `kid` against the keys published at
   `<base_url>/.well-known/jwks.json`,
2. verifying the RSASSA-PKCS1-v1_5 signature, and
3. validating the `iss`, `aud` and `exp`/`nbf` claims.

Signature verification and claim checks are delegated to
[`jwt-simple`](https://docs.rs/jwt-simple), built with its `pure-rust` feature
so the RustCrypto backend (not BoringSSL) is used on every target — it links
cleanly into a `wasm32-wasip2` component with no native dependencies. JWKS
fetching goes through `wasi:http/outgoing-handler` — the host (wasmCloud)
provides the transport.

## Usage

```toml
# Cargo.toml
[dependencies]
fusionauth_jwt_rs = { git = "https://github.com/bettyblocks/fusionauth_jwt_rs" }
```

### Self-contained (fetches JWKS over `wasi:http`, `wasm32` only)

```rust
use fusionauth_jwt_rs::{Validation, Verifier};

let validation = Validation::new()
    .issuer("bettyblocks.com")
    .audience("11111111-1111-1111-1111-111111111111"); // FusionAuth application id

let mut verifier = Verifier::new("https://auth.example.com", validation);

// Fetches + caches the JWKS, matches kid, verifies signature, validates claims.
// Refetches the JWKS once if the kid is unknown (key rotation), like the
// Elixir JWKS_Strategy.
let claims = verifier.verify_token(jwt)?;
println!("sub = {:?}, cas_token = {:?}", claims.sub, claims.get("cas_token"));
```

`Verifier` caches the JWKS in memory for the lifetime of the instance. Call
`verifier.invalidate_cache()` to force a refetch, or `verifier.set_jwks(jwks)`
to inject keys you fetched yourself.

### Bring-your-own-keys (pure, runs on any target)

If you fetch and cache the JWKS yourself (or want to unit-test), use the
I/O-free path. You supply the `Jwks` and the current time (unix seconds):

```rust
use fusionauth_jwt_rs::{Jwks, Validation, Verifier};

let jwks = Jwks::from_json(jwks_response_body)?;
let verifier = Verifier::new("https://auth.example.com", validation);
let claims = verifier.verify_with_jwks(jwt, &jwks, now_unix_seconds)?;
```

## wasmCloud / component wiring

This crate is a plain library (`rlib`). The **component that depends on it**
must import `wasi:http` so the `verify_token` fetch can resolve. A minimal
world:

```wit
// wit/world.wit
package example:fusionauth-consumer;

world component {
    // Required so JWKS fetching can resolve at link time.
    import wasi:http/outgoing-handler@0.2.0;
    // ... your own exports (e.g. wasi:http/incoming-handler) ...
}
```

Build the consuming component with the native component target:

```sh
cargo build --target wasm32-wasip2 --release
```

(Rust ≥ 1.82 emits a component directly for `wasm32-wasip2`; no
`cargo-component` required.) When deployed, give the component an HTTP-client
capability link in your wasmCloud manifest so its outgoing requests to
FusionAuth are satisfied.

## Differences from the Elixir library

This crate covers the **verification** core only:

- **Ported:** the default `JWKS_Strategy` — JWKS fetch, `kid`-matched RS256
  verification, refetch-once-on-unknown-`kid`, and `iss`/`aud`/`exp` validation.
- **Not ported:** the Plug / cookie handling, login handlers, and the
  `public-key` (certificate-store) strategy. Claims are returned to the caller
  ([`Claims`]); what to do on success (assign `cas_token`, etc.) is the caller's
  job — the equivalent of the Elixir `HandleLogin` behaviour.

## Development

```sh
cargo test                          # host tests of the pure verification path
cargo build --target wasm32-wasip2  # confirm the wasi:http path compiles
cargo clippy --all-targets
cargo clippy --target wasm32-wasip2
```

## License

MIT
