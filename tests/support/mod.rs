use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use totp_cli::{
    enrollment::{Algorithm, Enrollment},
    error::{AppError, Result},
    vault::{CredentialKind, Vault},
};
use zeroize::Zeroizing;

pub const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[derive(Clone, Default)]
pub struct MemoryVault {
    pub secrets: Arc<Mutex<BTreeMap<(CredentialKind, String), String>>>,
    pub calls: Arc<AtomicUsize>,
    pub fail_get: Arc<AtomicBool>,
    pub fail_put: Arc<AtomicBool>,
    pub fail_delete: Arc<AtomicBool>,
}

impl Vault for MemoryVault {
    fn get(&self, kind: CredentialKind, id: &str) -> Result<Option<Zeroizing<String>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_get.load(Ordering::SeqCst) {
            return Err(AppError::new("Injected read failure"));
        }
        Ok(self
            .secrets
            .lock()
            .unwrap()
            .get(&(kind, id.to_owned()))
            .cloned()
            .map(Zeroizing::new))
    }
    fn put(&self, kind: CredentialKind, id: &str, secret: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.secrets
            .lock()
            .unwrap()
            .insert((kind, id.to_owned()), secret.to_owned());
        if self.fail_put.load(Ordering::SeqCst) {
            Err(AppError::new("Injected write failure"))
        } else {
            Ok(())
        }
    }
    fn delete(&self, kind: CredentialKind, id: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(AppError::new("Injected deletion failure"));
        }
        self.secrets.lock().unwrap().remove(&(kind, id.to_owned()));
        Ok(())
    }
}

pub fn enrollment() -> Enrollment {
    Enrollment::new(
        SECRET,
        "alice@example.com",
        "Example",
        Algorithm::Sha1,
        8,
        30,
    )
    .unwrap()
}
