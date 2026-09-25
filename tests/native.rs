use totp_cli::vault::{NativeVault, Vault};
use uuid::Uuid;

const PUBLIC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PUBLIC_UPDATE: &str = "JBSWY3DPEHPK3PXP";

struct DisposableCredential {
    vault: NativeVault,
    id: String,
}

impl DisposableCredential {
    fn new() -> Self {
        assert!(
            cfg!(feature = "native-test"),
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
        let _ = self.vault.delete(&self.id);
    }
}

#[test]
#[ignore = "uses only a random disposable native credential; requires an unlocked OS store"]
fn native_roundtrip_update_and_missing_deletion() {
    let credential = DisposableCredential::new();
    let vault = &credential.vault;
    let identifier = &credential.id;

    assert!(vault.get(identifier).unwrap().is_none());
    vault.delete(identifier).unwrap();
    vault.put(identifier, PUBLIC_SECRET).unwrap();
    assert_eq!(
        vault.get(identifier).unwrap().unwrap().as_str(),
        PUBLIC_SECRET
    );
    vault.put(identifier, PUBLIC_UPDATE).unwrap();
    assert_eq!(
        vault.get(identifier).unwrap().unwrap().as_str(),
        PUBLIC_UPDATE
    );
    vault.delete(identifier).unwrap();
    assert!(vault.get(identifier).unwrap().is_none());
    vault.delete(identifier).unwrap();
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
        fn read(identifier: &str) -> Self {
            let target: Vec<u16> = format!(
                "totp-secret.{}/{identifier}",
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
        for secret in [PUBLIC_SECRET, PUBLIC_UPDATE] {
            credential.vault.put(&credential.id, secret).unwrap();
            let stored = ReadCredential::read(&credential.id);
            let descriptor = unsafe { stored.0.as_ref() };
            assert_eq!(descriptor.Type, CRED_TYPE_GENERIC);
            assert_eq!(descriptor.Persist, CRED_PERSIST_LOCAL_MACHINE);
        }
        credential.vault.delete(&credential.id).unwrap();
        assert!(credential.vault.get(&credential.id).unwrap().is_none());
    }
}
