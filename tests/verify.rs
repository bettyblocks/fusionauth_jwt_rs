//! End-to-end tests of the pure verification path (`verify_with_jwks`), which
//! runs on the host. The `wasi:http` fetching path is only reachable on
//! `wasm32` and is covered by integration in a wasmCloud host.
//!
//! `jsonwebtoken` validates `exp`/`nbf` against the system clock, so tokens are
//! signed relative to the current time rather than a fixed instant.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fusionauth_jwt_rs::{Error, Jwks, Validation, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, rand_core::OsRng};
use sha2::{Digest, Sha256};

const ISS: &str = "bettyblocks.com";
const AUD: &str = "11111111-1111-1111-1111-111111111111";

/// Current unix time in seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// One 2048-bit key generated for the whole test binary.
fn test_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).expect("generate test key"))
}

/// Build a JWKS document advertising the test key under `kid`/`alg`.
fn jwks_for(kid: &str, alg: &str) -> Jwks {
    let pubkey = test_key().to_public_key();
    let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
    let json = format!(
        r#"{{"keys":[{{"kid":"{kid}","kty":"RSA","alg":"{alg}","use":"sig","n":"{n}","e":"{e}"}}]}}"#
    );
    Jwks::from_json(json.as_bytes()).expect("parse jwks")
}

/// Sign a JWT with the test key.
fn sign_jwt(kid: &str, alg: &str, claims_json: &str) -> String {
    let header = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"{kid}"}}"#);
    let h = URL_SAFE_NO_PAD.encode(header);
    let p = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{h}.{p}");
    let hashed = Sha256::digest(signing_input.as_bytes());
    let sig = test_key()
        .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
        .expect("sign");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn claims(exp: i64) -> String {
    let iat = now();
    format!(
        r#"{{"iss":"{ISS}","aud":"{AUD}","sub":"user-42","exp":{exp},"iat":{iat},"cas_token":"cas-abc"}}"#
    )
}

fn verifier() -> Verifier {
    Verifier::new(
        "https://auth.example.com",
        Validation::new().issuer(ISS).audience(AUD),
    )
}

#[test]
fn verifies_valid_token_and_returns_claims() {
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS256", &claims(now() + 3600));

    let result = verifier()
        .verify_with_jwks(&jwt, &jwks)
        .expect("token should verify");

    assert_eq!(result.iss.as_deref(), Some(ISS));
    assert_eq!(result.sub.as_deref(), Some("user-42"));
    // Custom FusionAuth claims survive in `extra`.
    assert_eq!(
        result.get("cas_token").and_then(|v| v.as_str()),
        Some("cas-abc")
    );
}

#[test]
fn rejects_unknown_kid() {
    // JWKS only carries "id2", token signed under "id4".
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id4", "RS256", &claims(now() + 3600));

    match verifier().verify_with_jwks(&jwt, &jwks) {
        Err(Error::KidNotFound(kid)) => assert_eq!(kid, "id4"),
        other => panic!("expected KidNotFound, got {other:?}"),
    }
}

#[test]
fn rejects_expired_token() {
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS256", &claims(now() - 60));

    assert!(matches!(
        verifier().verify_with_jwks(&jwt, &jwks),
        Err(Error::TokenExpired)
    ));
}

#[test]
fn honours_leeway_on_expiry() {
    let jwks = jwks_for("id2", "RS256");
    // Expired 10s ago, but 60s of leeway keeps it valid.
    let jwt = sign_jwt("id2", "RS256", &claims(now() - 10));
    let v = Verifier::new(
        "https://auth.example.com",
        Validation::new().issuer(ISS).audience(AUD).leeway(60),
    );
    assert!(v.verify_with_jwks(&jwt, &jwks).is_ok());
}

#[test]
fn rejects_wrong_audience() {
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS256", &claims(now() + 3600));

    let v = Verifier::new(
        "https://auth.example.com",
        Validation::new().issuer(ISS).audience("some-other-app"),
    );
    assert!(matches!(
        v.verify_with_jwks(&jwt, &jwks),
        Err(Error::InvalidAudience)
    ));
}

#[test]
fn rejects_wrong_issuer() {
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS256", &claims(now() + 3600));

    let v = Verifier::new(
        "https://auth.example.com",
        Validation::new().issuer("evil.example").audience(AUD),
    );
    assert!(matches!(
        v.verify_with_jwks(&jwt, &jwks),
        Err(Error::InvalidIssuer)
    ));
}

#[test]
fn rejects_tampered_signature() {
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS256", &claims(now() + 3600));

    // Flip the first character of the signature segment. (Flipping the *last*
    // char can yield non-canonical base64, which decodes-error before the
    // signature is ever checked.)
    let sig_start = jwt.rfind('.').unwrap() + 1;
    let mut bytes = jwt.into_bytes();
    bytes[sig_start] = if bytes[sig_start] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();

    assert!(matches!(
        verifier().verify_with_jwks(&tampered, &jwks),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn rejects_algorithm_confusion() {
    // JWK pins RS256 but the header claims RS512: must be rejected even though
    // the signature itself is consistent with the header.
    let jwks = jwks_for("id2", "RS256");
    let jwt = sign_jwt("id2", "RS512", &claims(now() + 3600));

    assert!(matches!(
        verifier().verify_with_jwks(&jwt, &jwks),
        Err(Error::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn rejects_malformed_token() {
    let jwks = jwks_for("id2", "RS256");
    assert!(matches!(
        verifier().verify_with_jwks("not-a-jwt", &jwks),
        Err(Error::MalformedToken)
    ));
}
