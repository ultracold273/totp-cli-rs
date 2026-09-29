use totp_cli::vault::{CredentialKind, NativeVault, Vault};
use uuid::Uuid;

const PUBLIC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PUBLIC_UPDATE: &str = "JBSWY3DPEHPK3PXP";

struct DisposableCredential {
    vault: NativeVault,
    id: String,
}

impl DisposableCredential {
    fn new() -> Self {
        assert_eq!(
            totp_cli::vault::SERVICE_PREFIX,
            "local-totp-cli-rs-native-test",
            "Native tests require --features native-test to isolate OS credentials."
        );
        Self {
            vault: NativeVault::new(),
            id: format!("test-{}", Uuid::new_v4()),
        }
    }
}

impl Drop for DisposableCredential {
    fn drop(&mut self) {
        for kind in [CredentialKind::Totp, CredentialKind::Password] {
            let _ = self.vault.delete(kind, &self.id);
        }
    }
}

#[test]
#[ignore = "uses only a random disposable native credential; requires an unlocked OS store"]
fn native_roundtrip_update_and_missing_deletion() {
    let credential = DisposableCredential::new();
    let vault = &credential.vault;
    let identifier = &credential.id;

    for kind in [CredentialKind::Totp, CredentialKind::Password] {
        assert!(vault.get(kind, identifier).unwrap().is_none());
        vault.delete(kind, identifier).unwrap();
        vault.put(kind, identifier, PUBLIC_SECRET).unwrap();
        assert_eq!(
            vault.get(kind, identifier).unwrap().unwrap().as_str(),
            PUBLIC_SECRET
        );
        vault.put(kind, identifier, PUBLIC_UPDATE).unwrap();
        assert_eq!(
            vault.get(kind, identifier).unwrap().unwrap().as_str(),
            PUBLIC_UPDATE
        );
        vault.delete(kind, identifier).unwrap();
        assert!(vault.get(kind, identifier).unwrap().is_none());
        vault.delete(kind, identifier).unwrap();
    }
}

#[test]
#[ignore = "uses only disposable entries in the native-test credential namespace"]
fn native_password_and_totp_entries_are_isolated() {
    let credential = DisposableCredential::new();
    let vault = &credential.vault;
    let id = &credential.id;
    vault.put(CredentialKind::Totp, id, PUBLIC_SECRET).unwrap();
    vault
        .put(CredentialKind::Password, id, "Aa0123456789")
        .unwrap();
    assert_eq!(
        vault
            .get(CredentialKind::Password, id)
            .unwrap()
            .unwrap()
            .as_str(),
        "Aa0123456789"
    );
    vault.delete(CredentialKind::Password, id).unwrap();
    assert_eq!(
        vault
            .get(CredentialKind::Totp, id)
            .unwrap()
            .unwrap()
            .as_str(),
        PUBLIC_SECRET
    );
    vault.delete(CredentialKind::Totp, id).unwrap();
    assert!(vault.get(CredentialKind::Totp, id).unwrap().is_none());
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::ptr::{NonNull, null_mut};
    use windows_sys::Win32::Security::Credentials::{
        CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW,
        CredFree, CredReadW,
    };
    use zeroize::Zeroize;

    struct ReadCredential(NonNull<CREDENTIALW>);

    impl ReadCredential {
        fn read(kind: CredentialKind, identifier: &str) -> Self {
            let scope = match kind {
                CredentialKind::Totp => "",
                CredentialKind::Password => "password/",
            };
            let target: Vec<u16> = format!(
                "totp-secret.{}/{scope}{identifier}",
                totp_cli::vault::SERVICE_PREFIX
            )
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
            let mut credential = null_mut();
            let success =
                unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
            assert_ne!(
                success, 0,
                "could not inspect disposable Windows credential"
            );
            Self(NonNull::new(credential).expect("Windows returned an empty credential"))
        }
    }

    impl Drop for ReadCredential {
        fn drop(&mut self) {
            let credential = unsafe { self.0.as_mut() };
            let length = credential.CredentialBlobSize as usize;
            if length != 0
                && length <= CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
                && !credential.CredentialBlob.is_null()
            {
                unsafe { std::slice::from_raw_parts_mut(credential.CredentialBlob, length) }
                    .zeroize();
            }
            unsafe { CredFree(self.0.as_ptr().cast()) };
        }
    }

    #[test]
    #[ignore = "inspects only a random disposable Windows credential; requires a user logon session"]
    fn native_windows_persistence_is_local_machine() {
        let credential = DisposableCredential::new();
        for kind in [CredentialKind::Totp, CredentialKind::Password] {
            for secret in [PUBLIC_SECRET, PUBLIC_UPDATE] {
                credential.vault.put(kind, &credential.id, secret).unwrap();
                let stored = ReadCredential::read(kind, &credential.id);
                let descriptor = unsafe { stored.0.as_ref() };
                assert_eq!(descriptor.Type, CRED_TYPE_GENERIC);
                assert_eq!(descriptor.Persist, CRED_PERSIST_LOCAL_MACHINE);
            }
            credential.vault.delete(kind, &credential.id).unwrap();
            assert!(
                credential
                    .vault
                    .get(kind, &credential.id)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
