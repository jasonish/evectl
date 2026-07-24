// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

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
