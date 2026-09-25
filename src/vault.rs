use crate::error::{AppError, Result};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_os = "windows", test))]
mod windows;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
compile_error!("Native credential storage supports only macOS, Windows, and Linux.");

const USERNAME: &str = "totp-secret";
pub const SERVICE_PREFIX: &str = if cfg!(feature = "native-test") {
    "local-totp-cli-rs-native-test"
} else {
    "local-totp-cli-rs"
};

pub trait Vault: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<Zeroizing<String>>>;
    fn put(&self, id: &str, secret: &str) -> Result<()>;
    fn delete(&self, id: &str) -> Result<()>;
}

#[derive(Default)]
pub struct NativeVault;

impl NativeVault {
    pub const fn new() -> Self {
        Self
    }

    pub const fn label() -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "macOS Keychain"
        }
        #[cfg(target_os = "windows")]
        {
            "Windows Credential Manager (local machine)"
        }
        #[cfg(target_os = "linux")]
        {
            "Linux Secret Service"
        }
    }
}

impl Vault for NativeVault {
    fn get(&self, id: &str) -> Result<Option<Zeroizing<String>>> {
        let service = credential_service(id)?;
        #[cfg(target_os = "windows")]
        let result = windows::get(&service);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let result = with_credential(&service, |credential| credential.get_password());
        read_result(result)
    }

    fn put(&self, id: &str, secret: &str) -> Result<()> {
        let service = credential_service(id)?;
        #[cfg(target_os = "windows")]
        let result = windows::put(&service, secret);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let result = with_credential(&service, |credential| credential.set_password(secret));
        write_result(result)
    }

    fn delete(&self, id: &str) -> Result<()> {
        let service = credential_service(id)?;
        #[cfg(target_os = "windows")]
        let result = windows::delete(&service);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let result = with_credential(&service, |credential| credential.delete_credential());
        delete_result(result)
    }
}

fn credential_service(id: &str) -> Result<String> {
    let identifier = id.strip_prefix("test-").unwrap_or(id);
    let parsed =
        Uuid::parse_str(identifier).map_err(|_| AppError::new("Invalid credential identifier."))?;
    if parsed.hyphenated().to_string() != identifier {
        return Err(AppError::new("Invalid credential identifier."));
    }
    Ok(format!("{SERVICE_PREFIX}/{id}"))
}

fn read_result(result: keyring::Result<String>) -> Result<Option<Zeroizing<String>>> {
    match result {
        Ok(secret) => Ok(Some(Zeroizing::new(secret))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(sanitized_error(error, "Could not read the OS credential.")),
    }
}

fn write_result(result: keyring::Result<()>) -> Result<()> {
    result.map_err(|error| sanitized_error(error, "Could not save the OS credential."))
}

fn delete_result(result: keyring::Result<()>) -> Result<()> {
    match result {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(sanitized_error(
            error,
            "Could not remove the OS credential.",
        )),
    }
}

fn sanitized_error(error: keyring::Error, message: &'static str) -> AppError {
    if let keyring::Error::BadEncoding(mut bytes) = error {
        bytes.zeroize();
    }
    AppError::new(message)
}

#[cfg(target_os = "macos")]
fn with_credential<Output>(
    service: &str,
    operation: impl FnOnce(&dyn keyring::credential::CredentialApi) -> keyring::Result<Output>,
) -> keyring::Result<Output> {
    let credential =
        keyring::macos::MacCredential::new_with_target(Some("User"), service, USERNAME)?;
    operation(&credential)
}

#[cfg(target_os = "linux")]
fn with_credential<Output: Send>(
    service: &str,
    operation: impl FnOnce(&dyn keyring::credential::CredentialApi) -> keyring::Result<Output> + Send,
) -> keyring::Result<Output> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("totp-vault".to_owned())
            .spawn_scoped(scope, move || {
                let credential = keyring::secret_service::SsCredential::new_with_target(
                    Some("default"),
                    service,
                    USERNAME,
                )?;
                operation(&credential)
            })
            .map_err(|error| keyring::Error::PlatformFailure(Box::new(error)))?;
        worker.join().unwrap_or_else(|_| {
            Err(keyring::Error::PlatformFailure(Box::new(
                std::io::Error::other("Credential worker failed."),
            )))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring::{Error, credential::CredentialApi, mock::MockCredential};

    const PUBLIC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const PUBLIC_UPDATE: &str = "JBSWY3DPEHPK3PXP";
    const PUBLIC_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn native_construction_is_const_and_stateless() {
        const VAULT: NativeVault = NativeVault::new();
        fn require_send_sync(_: &(impl Send + Sync)) {}
        fn require_default<VaultType: Default + Send + Sync>() {
            require_send_sync(&VaultType::default());
        }

        require_send_sync(&VAULT);
        require_default::<NativeVault>();
        assert_eq!(std::mem::size_of::<NativeVault>(), 0);
        assert!(!NativeVault::label().is_empty());
    }

    #[test]
    fn service_names_are_isolated_and_canonical() {
        let namespace = if cfg!(feature = "native-test") {
            "local-totp-cli-rs-native-test"
        } else {
            "local-totp-cli-rs"
        };
        assert_eq!(
            credential_service(PUBLIC_ID).unwrap(),
            format!("{namespace}/{PUBLIC_ID}")
        );
        assert_eq!(
            credential_service(&format!("test-{PUBLIC_ID}")).unwrap(),
            format!("{namespace}/test-{PUBLIC_ID}")
        );
    }

    #[test]
    fn invalid_identifiers_fail_before_native_access() {
        let vault = NativeVault::new();
        for identifier in [
            "",
            "test-",
            "../another-service",
            "550e8400e29b41d4a716446655440000",
            "550E8400-E29B-41D4-A716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000\0",
            "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
            "test-test-550e8400-e29b-41d4-a716-446655440000",
            "secret\nbackend failure",
        ] {
            assert_eq!(
                credential_service(identifier).unwrap_err().to_string(),
                "Invalid credential identifier."
            );
            assert_eq!(
                vault.get(identifier).unwrap_err().to_string(),
                "Invalid credential identifier."
            );
            assert_eq!(
                vault
                    .put(identifier, PUBLIC_SECRET)
                    .unwrap_err()
                    .to_string(),
                "Invalid credential identifier."
            );
            assert_eq!(
                vault.delete(identifier).unwrap_err().to_string(),
                "Invalid credential identifier."
            );
        }
    }

    #[test]
    fn mock_roundtrip_update_and_missing_deletion() {
        let credential = MockCredential::default();

        assert!(read_result(credential.get_password()).unwrap().is_none());
        delete_result(credential.delete_credential()).unwrap();
        write_result(credential.set_password(PUBLIC_SECRET)).unwrap();
        assert_eq!(
            read_result(credential.get_password())
                .unwrap()
                .unwrap()
                .as_str(),
            PUBLIC_SECRET
        );
        write_result(credential.set_password(PUBLIC_UPDATE)).unwrap();
        assert_eq!(
            read_result(credential.get_password())
                .unwrap()
                .unwrap()
                .as_str(),
            PUBLIC_UPDATE
        );
        delete_result(credential.delete_credential()).unwrap();
        delete_result(credential.delete_credential()).unwrap();
        assert!(read_result(credential.get_password()).unwrap().is_none());
    }

    fn backend_errors() -> Vec<Error> {
        let ambiguous = MockCredential::default();
        ambiguous.set_password(PUBLIC_SECRET).unwrap();
        vec![
            Error::PlatformFailure(Box::new(std::io::Error::other(PUBLIC_SECRET))),
            Error::NoStorageAccess(Box::new(std::io::Error::other(PUBLIC_SECRET))),
            Error::BadEncoding(PUBLIC_SECRET.as_bytes().to_vec()),
            Error::TooLong(PUBLIC_SECRET.to_owned(), 42),
            Error::Invalid(PUBLIC_SECRET.to_owned(), "RAW OS ERROR".to_owned()),
            Error::Ambiguous(vec![Box::new(ambiguous)]),
        ]
    }

    #[test]
    fn backend_errors_never_expose_secrets_or_raw_details() {
        let credential = MockCredential::default();
        for error in backend_errors() {
            credential.set_error(error);
            let error = read_result(credential.get_password()).unwrap_err();
            assert_eq!(error.to_string(), "Could not read the OS credential.");
            assert!(!format!("{error:?}").contains(PUBLIC_SECRET));
            assert!(!format!("{error:?}").contains("RAW OS ERROR"));
            assert!(std::error::Error::source(&error).is_none());
        }
        for error in backend_errors() {
            credential.set_error(error);
            let error = write_result(credential.set_password(PUBLIC_SECRET)).unwrap_err();
            assert_eq!(error.to_string(), "Could not save the OS credential.");
            assert!(!format!("{error:?}").contains(PUBLIC_SECRET));
            assert!(std::error::Error::source(&error).is_none());
        }
        for error in backend_errors() {
            credential.set_error(error);
            let error = delete_result(credential.delete_credential()).unwrap_err();
            assert_eq!(error.to_string(), "Could not remove the OS credential.");
            assert!(!format!("{error:?}").contains(PUBLIC_SECRET));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn missing_write_is_an_error_not_success() {
        let credential = MockCredential::default();
        credential.set_error(Error::NoEntry);
        assert_eq!(
            write_result(credential.set_password(PUBLIC_SECRET))
                .unwrap_err()
                .to_string(),
            "Could not save the OS credential."
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_is_explicit_and_construction_only() {
        let service = credential_service(PUBLIC_ID).unwrap();
        with_credential(&service, |credential| {
            let credential = credential
                .as_any()
                .downcast_ref::<keyring::macos::MacCredential>()
                .unwrap();
            assert_eq!(credential.domain, keyring::macos::MacKeychainDomain::User);
            assert_eq!(credential.service, service);
            assert_eq!(credential.account, "totp-secret");
            Ok(())
        })
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_is_explicit_and_runs_off_the_calling_thread() {
        let calling_thread = std::thread::current().id();
        let service = credential_service(PUBLIC_ID).unwrap();
        with_credential(&service, |credential| {
            assert_ne!(std::thread::current().id(), calling_thread);
            let credential = credential
                .as_any()
                .downcast_ref::<keyring::secret_service::SsCredential>()
                .unwrap();
            assert_eq!(credential.attributes["service"], service);
            assert_eq!(credential.attributes["username"], "totp-secret");
            assert_eq!(credential.attributes["target"], "default");
            Ok(())
        })
        .unwrap();
    }
}
