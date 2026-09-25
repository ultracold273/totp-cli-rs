use keyring::{Error, Result};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 2560;

fn target_name(service: &str) -> Result<Vec<u16>> {
    if service.contains('\0') {
        return Err(invalid_credential());
    }
    Ok(format!("{}.{service}", super::USERNAME)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect())
}

fn encode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let max_units = MAX_CREDENTIAL_BYTES / 2;
    let unit_count = secret.encode_utf16().take(max_units + 1).count();
    if unit_count > max_units {
        return Err(Error::TooLong(
            "password".to_owned(),
            MAX_CREDENTIAL_BYTES as u32,
        ));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(unit_count * 2));
    encoded.extend(secret.encode_utf16().flat_map(u16::to_le_bytes));
    Ok(encoded)
}

fn decode_secret(blob: &[u8]) -> Result<String> {
    if blob.len() > MAX_CREDENTIAL_BYTES || blob.len() % 2 != 0 {
        return Err(invalid_credential());
    }
    let units = blob
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
    let mut decoded = Zeroizing::new(String::with_capacity(blob.len() / 2 * 3));
    for character in char::decode_utf16(units) {
        decoded.push(character.map_err(|_| invalid_credential())?);
    }
    Ok(std::mem::take(&mut *decoded))
}

fn invalid_credential() -> Error {
    Error::Invalid(
        "credential".to_owned(),
        "Invalid credential data.".to_owned(),
    )
}

#[cfg(target_os = "windows")]
pub(super) use platform::{delete, get, put};

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::ptr::{NonNull, null_mut};
    use windows_sys::Win32::{
        Foundation::{ERROR_NOT_FOUND, GetLastError},
        Security::Credentials::{
            CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
            CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
        },
    };
    use zeroize::Zeroize;

    const _: () = assert!(MAX_CREDENTIAL_BYTES == CRED_MAX_CREDENTIAL_BLOB_SIZE as usize);

    struct OwnedCredential(NonNull<CREDENTIALW>);

    impl OwnedCredential {
        fn read(target: &[u16]) -> Result<Self> {
            let mut credential = null_mut();
            if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
                return Err(last_error());
            }
            NonNull::new(credential)
                .map(Self)
                .ok_or_else(invalid_credential)
        }

        fn blob(&self) -> Result<&[u8]> {
            let credential = unsafe { self.0.as_ref() };
            let length = credential.CredentialBlobSize as usize;
            if length > MAX_CREDENTIAL_BYTES {
                return Err(invalid_credential());
            }
            if length == 0 {
                return Ok(&[]);
            }
            if credential.CredentialBlob.is_null() {
                return Err(invalid_credential());
            }
            Ok(unsafe { std::slice::from_raw_parts(credential.CredentialBlob, length) })
        }
    }

    impl Drop for OwnedCredential {
        fn drop(&mut self) {
            let credential = unsafe { self.0.as_mut() };
            let length = credential.CredentialBlobSize as usize;
            if length != 0 && length <= MAX_CREDENTIAL_BYTES && !credential.CredentialBlob.is_null()
            {
                unsafe { std::slice::from_raw_parts_mut(credential.CredentialBlob, length) }
                    .zeroize();
            }
            unsafe { CredFree(self.0.as_ptr().cast()) };
        }
    }

    struct WriteCredential {
        target: Vec<u16>,
        username: Vec<u16>,
        blob: Zeroizing<Vec<u8>>,
    }

    impl WriteCredential {
        fn new(service: &str, secret: &str) -> Result<Self> {
            Ok(Self {
                target: target_name(service)?,
                username: super::super::USERNAME
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect(),
                blob: encode_secret(secret)?,
            })
        }

        fn descriptor(&mut self) -> CREDENTIALW {
            CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: self.target.as_mut_ptr(),
                CredentialBlobSize: self.blob.len() as u32,
                CredentialBlob: self.blob.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                UserName: self.username.as_mut_ptr(),
                ..CREDENTIALW::default()
            }
        }
    }

    pub(in crate::vault) fn get(service: &str) -> Result<String> {
        let target = target_name(service)?;
        let credential = OwnedCredential::read(&target)?;
        decode_secret(credential.blob()?)
    }

    pub(in crate::vault) fn put(service: &str, secret: &str) -> Result<()> {
        let mut credential = WriteCredential::new(service, secret)?;
        if unsafe { CredWriteW(&credential.descriptor(), 0) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(in crate::vault) fn delete(service: &str) -> Result<()> {
        let target = target_name(service)?;
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    fn last_error() -> Error {
        error_from_code(unsafe { GetLastError() })
    }

    fn error_from_code(code: u32) -> Error {
        if code == ERROR_NOT_FOUND {
            Error::NoEntry
        } else {
            Error::PlatformFailure(Box::new(std::io::Error::other(
                "OS credential operation failed.",
            )))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

        #[test]
        fn every_write_descriptor_uses_local_machine_persistence() {
            let service = "local-totp-cli-rs/test-550e8400-e29b-41d4-a716-446655440000";
            for secret in ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "JBSWY3DPEHPK3PXP"] {
                let mut credential = WriteCredential::new(service, secret).unwrap();
                let descriptor = credential.descriptor();
                assert_eq!(descriptor.Persist, CRED_PERSIST_LOCAL_MACHINE);
                assert_eq!(descriptor.Type, CRED_TYPE_GENERIC);
                assert_eq!(descriptor.CredentialBlobSize as usize, secret.len() * 2);
                assert_eq!(descriptor.TargetName, credential.target.as_mut_ptr());
                assert_eq!(descriptor.UserName, credential.username.as_mut_ptr());
                assert_eq!(descriptor.Flags, 0);
            }
        }

        #[test]
        fn only_not_found_maps_to_missing() {
            assert!(matches!(error_from_code(ERROR_NOT_FOUND), Error::NoEntry));
            assert!(matches!(
                error_from_code(ERROR_ACCESS_DENIED),
                Error::PlatformFailure(_)
            ));
            assert!(matches!(error_from_code(0), Error::PlatformFailure(_)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_uses_the_keyring_service_and_username_convention() {
        let service = "local-totp-cli-rs/test-550e8400-e29b-41d4-a716-446655440000";
        let target = target_name(service).unwrap();
        assert_eq!(target.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&target[..target.len() - 1]).unwrap(),
            format!("totp-secret.{service}")
        );
        assert_eq!(target.iter().filter(|unit| **unit == 0).count(), 1);
    }

    #[test]
    fn target_rejects_embedded_nuls() {
        assert!(target_name("local-totp-cli-rs/test-public\0other").is_err());
    }

    #[test]
    fn utf16_little_endian_encoding_matches_keyring() {
        assert_eq!(
            encode_secret("Aé😀").unwrap().as_slice(),
            &[0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde]
        );
        for secret in [
            "",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "公开测试😀",
            "public\0test",
        ] {
            assert_eq!(
                decode_secret(&encode_secret(secret).unwrap()).unwrap(),
                secret
            );
        }
    }

    #[test]
    fn secret_limit_counts_utf16_bytes_not_characters() {
        let ascii_limit = "A".repeat(MAX_CREDENTIAL_BYTES / 2);
        assert_eq!(
            encode_secret(&ascii_limit).unwrap().len(),
            MAX_CREDENTIAL_BYTES
        );
        assert!(encode_secret(&format!("{ascii_limit}A")).is_err());

        let supplementary_limit = "😀".repeat(MAX_CREDENTIAL_BYTES / 4);
        assert_eq!(
            encode_secret(&supplementary_limit).unwrap().len(),
            MAX_CREDENTIAL_BYTES
        );
        assert!(encode_secret(&format!("{supplementary_limit}😀")).is_err());
    }

    #[test]
    fn malformed_or_oversized_blobs_are_rejected() {
        for blob in [
            vec![0x41],
            vec![0x00, 0xd8],
            vec![0x00, 0xdc],
            vec![0x41, 0x00, 0x00, 0xd8],
            vec![0; MAX_CREDENTIAL_BYTES + 2],
        ] {
            assert!(decode_secret(&blob).is_err());
        }
    }
}
