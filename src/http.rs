// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! HTTP client construction and downloads.

use std::io::{Read, Write};

use crate::prelude::*;

/// Return a reqwest client builder that trusts the system certificate
/// store merged with the bundled Mozilla root certificates.
///
/// With the merged roots, certificate verification works on hosts
/// without ca-certificates installed while still honoring any locally
/// installed CAs. All HTTP clients should be built from this builder.
pub(crate) fn client_builder() -> reqwest::blocking::ClientBuilder {
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| reqwest::Certificate::from_der(der).expect("invalid bundled root certificate"));
    reqwest::blocking::Client::builder().tls_certs_merge(roots)
}

/// Download `url` into `dest`, failing on a non-success HTTP status.
/// `progress` is called after each chunk with the bytes written so far
/// and the content length, if the server sent one.
pub(crate) fn download(
    url: &str,
    dest: &mut dyn Write,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<()> {
    let mut response = client_builder().build()?.get(url).send()?;
    if !response.status().is_success() {
        bail!("HTTP {}", response.status());
    }
    let total = response.content_length();
    let mut downloaded = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let n = response.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        dest.write_all(&buffer[..n])?;
        downloaded += n as u64;
        progress(downloaded, total);
    }
    dest.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Building the client parses the bundled roots and constructs the
    /// TLS verifier, catching bad bundled certificates without touching
    /// the network.
    #[test]
    fn test_client_builder() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        client_builder().build().unwrap();
    }
}
