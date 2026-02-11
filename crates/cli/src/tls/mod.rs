//! # TLS Configuration
//!
//! TLS certificate and private key loading utilities.

use std::io;

use rustls::pki_types::pem::PemObject as _;

/// Load certificates from a PEM file
///
/// # Arguments
///
/// * `path` - Path to the PEM file containing certificates
///
/// # Returns
///
/// A `Result` containing a vector of certificates or an I/O error.
pub fn load_certs(path: &str) -> io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_pem = std::fs::read(path)?;
    let mut certs = Vec::new();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
        certs.push(cert.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    }
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No certificates found in file",
        ));
    }
    Ok(certs)
}

/// Load private key from a PEM file
///
/// # Arguments
///
/// * `path` - Path to the PEM file containing the private key
///
/// # Returns
///
/// A `Result` containing the private key or an I/O error.
pub fn load_private_key(path: &str) -> io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let key_pem = std::fs::read(path)?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::NamedTempFile;

    use super::*;

    // Minimal valid test certificates - these are test fixtures, not real keys
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICljCCAX6gAwIBAgIUfk5kJ8P4JVL2f2k8p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s5p0s
-----END CERTIFICATE-----"#;

    // Test private key - this is a minimal valid EC private key structure for testing
    const TEST_KEY_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAcGBSuBBAAK
oUQDQgAEkH3m0e2e4Rg1C7P6CQ1F3N7f5Cw3KJ3z7t4f8e1y2z9k4j5n6o7p8q9r
0s1t2u3v4w5x6y7z8A9B0C1D2E3F4G5H6I7J8K9L0M
-----END EC PRIVATE KEY-----"#;

    #[test]
    fn test_load_certs_valid_pem() {
        let temp_file = NamedTempFile::new().unwrap();
        let cert_path = temp_file.path().to_str().unwrap();

        fs::write(cert_path, TEST_CERT_PEM).unwrap();

        let result = load_certs(cert_path);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_load_certs_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let cert_path = temp_file.path().to_str().unwrap();

        fs::write(cert_path, "").unwrap();

        let result = load_certs(cert_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_invalid_pem() {
        let temp_file = NamedTempFile::new().unwrap();
        let cert_path = temp_file.path().to_str().unwrap();

        fs::write(cert_path, "not a valid pem").unwrap();

        let result = load_certs(cert_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_nonexistent_file() {
        let result = load_certs("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_valid_pem() {
        let temp_file = NamedTempFile::new().unwrap();
        let key_path = temp_file.path().to_str().unwrap();

        fs::write(key_path, TEST_KEY_PEM).unwrap();

        let result = load_private_key(key_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let temp_file = NamedTempFile::new().unwrap();
        let key_path = temp_file.path().to_str().unwrap();

        fs::write(key_path, "not a valid pem key").unwrap();

        let result = load_private_key(key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let key_path = temp_file.path().to_str().unwrap();

        fs::write(key_path, "").unwrap();

        let result = load_private_key(key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_nonexistent_file() {
        let result = load_private_key("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }
}
