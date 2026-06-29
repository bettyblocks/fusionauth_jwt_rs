//! JWKS fetching over `wasi:http/outgoing-handler`.
//!
//! This module only compiles for `wasm32` targets. When linked into a
//! wasmCloud component, the host satisfies the `wasi:http` import; the
//! component's world must declare `import wasi:http/outgoing-handler`.

use wasi::http::outgoing_handler;
use wasi::http::types::{Fields, IncomingBody, Method, OutgoingRequest, Scheme};
use wasi::io::streams::StreamError;

use crate::error::Error;
use crate::jwks::Jwks;

const JWKS_PATH: &str = "/.well-known/jwks.json";
const READ_CHUNK: u64 = 8 * 1024;

/// Fetch and parse the JWKS from `<base_url>/.well-known/jwks.json`.
pub fn fetch_jwks(base_url: &str) -> Result<Jwks, Error> {
    let (scheme, authority, base_path) = parse_url(base_url)?;
    let path = format!("{}{}", base_path.trim_end_matches('/'), JWKS_PATH);

    let request = OutgoingRequest::new(Fields::new());
    request
        .set_method(&Method::Get)
        .map_err(|_| Error::Http("could not set method".into()))?;
    request
        .set_scheme(Some(&scheme))
        .map_err(|_| Error::Http("could not set scheme".into()))?;
    request
        .set_authority(Some(&authority))
        .map_err(|_| Error::Http("could not set authority".into()))?;
    request
        .set_path_with_query(Some(&path))
        .map_err(|_| Error::Http("could not set path".into()))?;

    let future = outgoing_handler::handle(request, None)
        .map_err(|e| Error::Http(format!("request failed: {e:?}")))?;

    // Block until the host has produced a response.
    future.subscribe().block();

    let response = future
        .get()
        .ok_or_else(|| Error::Http("response future not ready after block".into()))?
        .map_err(|_| Error::Http("response future already consumed".into()))?
        .map_err(|e| Error::Http(format!("response error: {e:?}")))?;

    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(Error::Http(format!("unexpected status {status}")));
    }

    let body = response
        .consume()
        .map_err(|_| Error::Http("could not consume response body".into()))?;
    let bytes = read_body(&body)?;

    Jwks::from_json(&bytes)
}

/// Drain an incoming HTTP body to bytes.
fn read_body(body: &IncomingBody) -> Result<Vec<u8>, Error> {
    let stream = body
        .stream()
        .map_err(|_| Error::Http("could not open body stream".into()))?;

    let mut buf = Vec::new();
    loop {
        match stream.blocking_read(READ_CHUNK) {
            Ok(chunk) => buf.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(StreamError::LastOperationFailed(e)) => {
                return Err(Error::Http(format!("body read failed: {}", e.to_debug_string())));
            }
        }
    }
    Ok(buf)
}

/// Split a base URL into `wasi:http` scheme, authority (host[:port]) and path.
/// A bare host (no `scheme://`) defaults to HTTPS.
fn parse_url(url: &str) -> Result<(Scheme, String, String), Error> {
    let (scheme_str, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("https", url),
    };

    let scheme = match scheme_str.to_ascii_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => Scheme::Other(other.to_string()),
    };

    if rest.is_empty() {
        return Err(Error::Http("empty authority in base_url".into()));
    }

    let (authority, path) = match rest.find('/') {
        Some(idx) => (rest[..idx].to_string(), rest[idx..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    Ok((scheme, authority, path))
}
