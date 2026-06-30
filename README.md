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

Verification — signature, algorithm, and the `iss`/`aud`/`exp`/`nbf` claims —
is delegated to [`jsonwebtoken`](https://docs.rs/jsonwebtoken), built with its
`rust_crypto` backend so the RSA crypto is pure Rust (no `ring`/`aws-lc-rs`/C).
It builds and runs on `wasm32-wasip2` with only `wasi:*` imports (time resolves
to `wasi:clocks`), so no JavaScript host is required.

### JWKS fetch backends

`Verifier::verify_token` fetches the JWKS itself. One backend is compiled per
target:

| Target | Transport | Notes |
| --- | --- | --- |
| `wasm32-wasip2` | `wasi:http/outgoing-handler@0.2` (`wasi` crate) | host provides transport |
| `wasm32-wasip3` | `wasi:http` 0.3 (`wasi-fetch`) | async, bridged via `block_on`; not yet build-verified |
| native (non-wasm) | blocking `ureq` | behind the **`native-http`** feature (off by default) |

If you fetch the JWKS yourself, use `verify_with_jwks` instead — it needs no
backend and works on every target.

## Usage

```toml
# Cargo.toml
[dependencies]
fusionauth_jwt_rs = { git = "https://github.com/bettyblocks/fusionauth_jwt_rs" }
```

### Self-contained (fetches the JWKS itself)

Available on the wasm targets, and on native with the `native-http` feature:

```toml
# Cargo.toml — for native (non-wasm) use:
fusionauth_jwt_rs = { git = "...", features = ["native-http"] }
```

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
I/O-free path. You supply the `Jwks`; `exp`/`nbf` are checked against the
system clock:

```rust
use fusionauth_jwt_rs::{Jwks, Validation, Verifier};

let jwks = Jwks::from_json(jwks_response_body)?;
let verifier = Verifier::new("https://auth.example.com", validation);
let claims = verifier.verify_with_jwks(jwt, &jwks)?;
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
cargo test                                  # host tests of the pure verification path
cargo build --features native-http          # native fetch backend (ureq)
cargo build --target wasm32-wasip2          # confirm the wasi:http 0.2 path compiles
cargo clippy --all-targets
cargo clippy --target wasm32-wasip2
```

The `wasm32-wasip3` backend (`wasi:http` 0.3) is gated on `target_env = "p3"`;
building it needs a `wasm32-wasip3` toolchain (currently built from source on
nightly), which is why it is not part of the routine checks above.

## License

MIT
