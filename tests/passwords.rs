mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use support::{MemoryVault, SECRET, enrollment};
use tempfile::tempdir;
use totp_cli::{
    error::{AppError, Result},
    password::{DEFAULT_LENGTH, MAX_LENGTH},
    store::{PasswordGeneration, Store},
    vault::{CredentialKind, Vault},
};
use zeroize::Zeroizing;

fn index(directory: &Path) -> Vec<u8> {
    fs::read(directory.join("accounts.json")).unwrap()
}

#[test]
fn password_only_account_roundtrips_without_totp_or_secret_metadata() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    assert_eq!(
        store
            .generate_password("Work", DEFAULT_LENGTH, false)
            .unwrap(),
        PasswordGeneration::Generated
    );
    let password = store.get_password("WORK").unwrap();
    assert_eq!(password.as_str().len(), 12);
    let calls = vault.calls.load(Ordering::SeqCst);
    let accounts = store.list().unwrap();
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].alias, "Work");
    assert!(accounts[0].totp.is_none());
    assert!(accounts[0].password_id.is_some());
    assert!(accounts[0].pending_password_deletions.is_empty());
    assert!(
        !String::from_utf8(index(directory.path()))
            .unwrap()
            .contains(password.as_str())
    );
    assert!(!format!("{password:?}").contains(password.as_str()));
    let summary = serde_json::to_value(accounts[0].summary()).unwrap();
    assert_eq!(summary["has_totp"], false);
    assert_eq!(summary["has_password"], true);
    for key in [
        "password_id",
        "pending_password_deletions",
        "algorithm",
        "digits",
        "period",
    ] {
        assert!(summary.get(key).is_none());
    }
    assert!(
        store
            .get("work")
            .unwrap_err()
            .to_string()
            .contains("no TOTP")
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
}

#[test]
fn enrolling_a_password_account_preserves_password_and_rejects_totp_replacement() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("Work", 12, false).unwrap();
    let password = store.get_password("work").unwrap();
    let before = store.list().unwrap().remove(0);
    store.enroll("WORK", &enrollment()).unwrap();
    let after = store.list().unwrap().remove(0);
    assert_eq!(before.id, after.id);
    assert_eq!(before.password_id, after.password_id);
    assert!(store.get_password("work").unwrap().as_str() == password.as_str());
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    let calls = vault.calls.load(Ordering::SeqCst);
    let metadata = index(directory.path());
    assert!(store.enroll("work", &enrollment()).is_err());
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
    assert_eq!(index(directory.path()), metadata);
}

#[test]
fn failed_enrollment_index_commit_preserves_existing_password() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let before = index(directory.path());
    let password = store.get_password("work").unwrap();
    let failing = Store::new(
        directory.path().to_owned(),
        FaultVault::new(vault.clone(), directory.path(), Fault::IndexAfterPut),
    );
    assert!(failing.enroll("work", &enrollment()).is_err());
    restore_index(directory.path());
    assert_eq!(index(directory.path()), before);
    assert!(store.get_password("work").unwrap().as_str() == password.as_str());
    assert!(store.get("work").is_err());
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn adding_password_preserves_totp_credentials_and_flat_summary_fields() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("Work", &enrollment()).unwrap();
    let id = store.list().unwrap()[0].id.clone();
    store.generate_password("work", 12, false).unwrap();
    let accounts = store.list().unwrap();
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].alias, "Work");
    assert_eq!(store.get("WORK").unwrap().secret(), SECRET);
    assert_eq!(vault.secrets.lock().unwrap().len(), 2);
    let summary = serde_json::to_value(accounts[0].summary()).unwrap();
    assert_eq!(summary["account"], "alice@example.com");
    assert_eq!(summary["issuer"], "Example");
    assert_eq!(summary["algorithm"], "SHA1");
    assert_eq!(summary["digits"], 8);
    assert_eq!(summary["period"], 30);
    assert_eq!(summary["has_totp"], true);
    assert_eq!(summary["has_password"], true);
    store.remove_password("WORK").unwrap();
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn replacement_is_explicit_and_uses_a_new_password_reference() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("Straße", 12, false).unwrap();
    let before = index(directory.path());
    let previous = store.get_password("STRASSE").unwrap();
    let record = store.list().unwrap().remove(0);
    let old_id = record.password_id.unwrap();
    let calls = vault.calls.load(Ordering::SeqCst);
    assert!(
        store
            .generate_password("strasse", 20, false)
            .unwrap_err()
            .to_string()
            .contains("--replace")
    );
    assert_eq!(calls, vault.calls.load(Ordering::SeqCst));
    assert_eq!(index(directory.path()), before);
    assert!(store.get_password("strasse").unwrap().as_str() == previous.as_str());
    store.generate_password("STRASSE", 20, true).unwrap();
    assert_eq!(store.get_password("strasse").unwrap().as_str().len(), 20);
    let replacement = store.list().unwrap().remove(0);
    assert_eq!(replacement.id, record.id);
    assert_ne!(replacement.password_id.as_ref().unwrap(), &old_id);
    let secrets = vault.secrets.lock().unwrap();
    assert!(!secrets.contains_key(&(CredentialKind::Password, old_id)));
    assert_eq!(secrets.len(), 1);
}

#[test]
fn removing_last_password_preserves_metadata_and_allows_regeneration() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("user1", 12, false).unwrap();
    let id = store.list().unwrap()[0].id.clone();
    store.remove_password("user1").unwrap();
    let accounts = store.list().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert!(accounts[0].totp.is_none());
    assert!(accounts[0].password_id.is_none());
    assert!(vault.secrets.lock().unwrap().is_empty());
    assert!(store.get_password("user1").is_err());
    assert!(store.remove_password("user1").is_err());
    store.generate_password("USER1", 24, false).unwrap();
    assert_eq!(store.get_password("user1").unwrap().as_str().len(), 24);
    store.remove("user1").unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(vault.secrets.lock().unwrap().is_empty());
}

#[test]
fn invalid_requests_and_missing_accounts_do_not_create_files_or_touch_vault() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("missing");
    let vault = MemoryVault::default();
    let store = Store::new(path.clone(), vault.clone());
    for length in [0, 11, MAX_LENGTH + 1, usize::MAX] {
        assert!(store.generate_password("user1", length, false).is_err());
    }
    for alias in ["", "../user", "user/1", "user name"] {
        assert!(store.generate_password(alias, 12, false).is_err());
    }
    assert!(store.get_password("missing").is_err());
    assert!(store.remove_password("missing").is_err());
    assert!(store.enroll("missing", &enrollment()).is_err());
    assert!(!path.exists());
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn version_one_reads_do_not_migrate_but_password_writes_preserve_legacy_totp_target() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    let id = "74946511-8151-43b2-bf2e-83591d7480f2";
    let legacy = format!(
        r#"{{"format":"local-totp-cli-rs","version":1,"accounts":[{{"id":"{id}","alias":"work","account":"alice","issuer":"Company","algorithm":"SHA1","digits":8,"period":30}}]}}"#
    );
    fs::write(directory.path().join("accounts.json"), &legacy).unwrap();
    vault.put(CredentialKind::Totp, id, SECRET).unwrap();
    assert_eq!(store.list().unwrap()[0].id, id);
    assert_eq!(
        store.get("work").unwrap().code_at(59.0).unwrap().0,
        "94287082"
    );
    assert_eq!(index(directory.path()), legacy.as_bytes());
    store.generate_password("work", 12, false).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&index(directory.path())).unwrap();
    assert_eq!(document["version"], 2);
    assert_eq!(document["accounts"][0]["id"], id);
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    assert_eq!(vault.secrets.lock().unwrap().len(), 2);
}

#[test]
fn password_metadata_rejects_invalid_duplicate_and_unknown_references() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&index(directory.path())).unwrap();
    let password_id = original["accounts"][0]["password_id"].clone();
    let mut cases = Vec::new();
    for (key, value) in [
        ("password_id", serde_json::json!("../SECRET_MARKER")),
        ("password_id", original["accounts"][0]["id"].clone()),
        (
            "pending_password_deletions",
            serde_json::json!([password_id]),
        ),
        ("password", serde_json::json!("SECRET_MARKER")),
        ("totp", serde_json::json!({"algorithm":"SHA1"})),
    ] {
        let mut document = original.clone();
        document["accounts"][0][key] = value;
        cases.push(document);
    }
    let mut duplicate = original.clone();
    let mut other = original["accounts"][0].clone();
    other["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    other["alias"] = serde_json::json!("another");
    duplicate["accounts"].as_array_mut().unwrap().push(other);
    cases.push(duplicate);
    let calls = vault.calls.load(Ordering::SeqCst);
    for document in cases {
        let content = document.to_string();
        fs::write(directory.path().join("accounts.json"), &content).unwrap();
        let error = store.generate_password("new", 12, false).unwrap_err();
        assert!(!error.to_string().contains("SECRET_MARKER"));
        assert_eq!(index(directory.path()), content.as_bytes());
    }
    assert_eq!(calls, vault.calls.load(Ordering::SeqCst));
}

#[test]
fn failed_partial_write_preserves_the_previous_password_and_index() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let before = index(directory.path());
    let password = store.get_password("work").unwrap();
    vault.fail_put.store(true, Ordering::SeqCst);
    let error = store
        .generate_password("work", 20, true)
        .unwrap_err()
        .to_string();
    assert!(!error.contains(password.as_str()));
    assert!(!error.contains("Injected"));
    assert_eq!(index(directory.path()), before);
    assert!(store.get_password("work").unwrap().as_str() == password.as_str());
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn failed_new_credential_cleanup_is_explicit_and_does_not_replace_the_old_reference() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let before = index(directory.path());
    vault.fail_put.store(true, Ordering::SeqCst);
    vault.fail_delete.store(true, Ordering::SeqCst);
    let error = store
        .generate_password("work", 20, true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("cleanup failed"));
    assert!(error.contains("previous password reference is unchanged"));
    assert_eq!(index(directory.path()), before);
    for secret in vault.secrets.lock().unwrap().values() {
        assert!(!error.contains(secret));
    }
}

#[test]
fn replacement_cleanup_can_be_retried_without_regenerating_the_saved_password() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    vault.fail_delete.store(true, Ordering::SeqCst);
    let error = store
        .generate_password("work", 20, true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("generated password is saved"));
    assert!(error.contains("Retry"));
    let saved = store.get_password("work").unwrap();
    assert_eq!(saved.as_str().len(), 20);
    assert_eq!(store.list().unwrap()[0].pending_password_deletions.len(), 1);
    assert_eq!(vault.secrets.lock().unwrap().len(), 2);
    vault.fail_delete.store(false, Ordering::SeqCst);
    assert_eq!(
        store.generate_password("work", 20, true).unwrap(),
        PasswordGeneration::CleanupCompleted
    );
    assert!(store.get_password("work").unwrap().as_str() == saved.as_str());
    assert!(
        store.list().unwrap()[0]
            .pending_password_deletions
            .is_empty()
    );
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn password_removal_cleanup_is_persisted_and_retryable_without_touching_totp() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    store.generate_password("work", 12, false).unwrap();
    vault.fail_delete.store(true, Ordering::SeqCst);
    assert!(
        store
            .remove_password("work")
            .unwrap_err()
            .to_string()
            .contains("Retry")
    );
    let record = store.list().unwrap().remove(0);
    assert!(record.password_id.is_none());
    assert_eq!(record.pending_password_deletions.len(), 1);
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    vault.fail_delete.store(false, Ordering::SeqCst);
    store.remove_password("work").unwrap();
    assert!(
        store.list().unwrap()[0]
            .pending_password_deletions
            .is_empty()
    );
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn missing_corrupt_and_unavailable_passwords_fail_without_fallback_or_leaks() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    store.generate_password("work", 12, false).unwrap();
    let id = store.list().unwrap()[0].password_id.clone().unwrap();
    vault.fail_get.store(true, Ordering::SeqCst);
    let error = store.get_password("work").unwrap_err().to_string();
    assert!(!error.contains("Injected"));
    vault.fail_get.store(false, Ordering::SeqCst);
    vault.secrets.lock().unwrap().insert(
        (CredentialKind::Password, id.clone()),
        "SECRET_MARKER".to_owned(),
    );
    let error = store.get_password("work").unwrap_err().to_string();
    assert!(!error.contains("SECRET_MARKER"));
    assert!(error.contains("invalid data"));
    vault
        .secrets
        .lock()
        .unwrap()
        .remove(&(CredentialKind::Password, id));
    assert!(
        store
            .get_password("work")
            .unwrap_err()
            .to_string()
            .contains("missing")
    );
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    store.remove_password("work").unwrap();
}

#[test]
fn account_removal_cleans_active_and_pending_passwords_and_totp() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    store.generate_password("work", 12, false).unwrap();
    vault.fail_delete.store(true, Ordering::SeqCst);
    assert!(store.generate_password("work", 20, true).is_err());
    vault.fail_delete.store(false, Ordering::SeqCst);
    store.remove("work").unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(vault.secrets.lock().unwrap().is_empty());
}

#[test]
fn concurrent_password_generation_for_one_alias_never_silently_replaces() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Arc::new(Store::new(directory.path().to_owned(), vault.clone()));
    let succeeded = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                scope.spawn(move || store.generate_password("work", 12, false).is_ok())
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(succeeded, 1);
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    IndexAfterPut,
    IndexAfterDelete,
    TotpDelete,
}

struct FaultVault {
    vault: MemoryVault,
    directory: PathBuf,
    fault: Fault,
    fired: AtomicBool,
}

impl FaultVault {
    fn new(vault: MemoryVault, directory: &Path, fault: Fault) -> Self {
        Self {
            vault,
            directory: directory.to_owned(),
            fault,
            fired: AtomicBool::new(false),
        }
    }

    fn disrupt_index(&self) {
        if !self.fired.swap(true, Ordering::SeqCst) {
            fs::rename(
                self.directory.join("accounts.json"),
                self.directory.join("saved.json"),
            )
            .unwrap();
            fs::create_dir(self.directory.join("accounts.json")).unwrap();
        }
    }
}

impl Vault for FaultVault {
    fn get(&self, kind: CredentialKind, id: &str) -> Result<Option<Zeroizing<String>>> {
        self.vault.get(kind, id)
    }

    fn put(&self, kind: CredentialKind, id: &str, secret: &str) -> Result<()> {
        self.vault.put(kind, id, secret)?;
        if self.fault == Fault::IndexAfterPut {
            self.disrupt_index();
        }
        Ok(())
    }

    fn delete(&self, kind: CredentialKind, id: &str) -> Result<()> {
        if self.fault == Fault::TotpDelete && kind == CredentialKind::Totp {
            return Err(AppError::new("Injected TOTP deletion failure"));
        }
        self.vault.delete(kind, id)?;
        if self.fault == Fault::IndexAfterDelete {
            self.disrupt_index();
        }
        Ok(())
    }
}

fn restore_index(directory: &Path) {
    fs::remove_dir(directory.join("accounts.json")).unwrap();
    fs::rename(
        directory.join("saved.json"),
        directory.join("accounts.json"),
    )
    .unwrap();
}

#[test]
fn failed_replacement_index_commit_rolls_back_only_the_new_password() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let before = index(directory.path());
    let previous = store.get_password("work").unwrap();
    let failing = Store::new(
        directory.path().to_owned(),
        FaultVault::new(vault.clone(), directory.path(), Fault::IndexAfterPut),
    );
    assert!(failing.generate_password("work", 20, true).is_err());
    restore_index(directory.path());
    assert_eq!(index(directory.path()), before);
    assert!(store.get_password("work").unwrap().as_str() == previous.as_str());
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
}

#[test]
fn cleanup_index_commit_failure_is_retryable_after_the_old_password_was_deleted() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.generate_password("work", 12, false).unwrap();
    let failing = Store::new(
        directory.path().to_owned(),
        FaultVault::new(vault.clone(), directory.path(), Fault::IndexAfterDelete),
    );
    assert!(
        failing
            .generate_password("work", 20, true)
            .unwrap_err()
            .to_string()
            .contains("cleanup")
    );
    restore_index(directory.path());
    let saved = store.get_password("work").unwrap();
    assert_eq!(saved.as_str().len(), 20);
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
    assert_eq!(
        store.generate_password("work", 20, true).unwrap(),
        PasswordGeneration::CleanupCompleted
    );
    assert!(store.get_password("work").unwrap().as_str() == saved.as_str());
    assert!(
        store.list().unwrap()[0]
            .pending_password_deletions
            .is_empty()
    );
}

#[test]
fn partial_account_deletion_retains_metadata_for_retry() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    store.generate_password("work", 12, false).unwrap();
    let before = index(directory.path());
    let failing = Store::new(
        directory.path().to_owned(),
        FaultVault::new(vault.clone(), directory.path(), Fault::TotpDelete),
    );
    assert!(
        failing
            .remove("work")
            .unwrap_err()
            .to_string()
            .contains("Retry")
    );
    assert_eq!(index(directory.path()), before);
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
    store.remove("work").unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(vault.secrets.lock().unwrap().is_empty());
}
