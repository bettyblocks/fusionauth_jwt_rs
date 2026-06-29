//! RSASSA-PKCS1-v1_5 signature verification (RS256/RS384/RS512), pure Rust so
//! it links cleanly into a WASI component.

use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::Error;

/// Verify the JWT signature over `signing_input` (`header.payload`) using the
/// RSA public key, selecting the digest from the JOSE `alg`.
pub fn verify_signature(
    alg: &str,
    key: &RsaPublicKey,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), Error> {
    let data = signing_input.as_bytes();

    let (scheme, hashed): (Pkcs1v15Sign, Vec<u8>) = match alg {
        "RS256" => (Pkcs1v15Sign::new::<Sha256>(), Sha256::digest(data).to_vec()),
        "RS384" => (Pkcs1v15Sign::new::<Sha384>(), Sha384::digest(data).to_vec()),
        "RS512" => (Pkcs1v15Sign::new::<Sha512>(), Sha512::digest(data).to_vec()),
        other => return Err(Error::UnsupportedAlgorithm(other.to_string())),
    };

    key.verify(scheme, &hashed, signature)
        .map_err(|_| Error::InvalidSignature)
}
