mod support;

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use support::{MemoryVault, SECRET, enrollment};
use tempfile::tempdir;
use totp_cli::{
    enrollment::{Algorithm, Enrollment},
    error::Result,
    store::Store,
    vault::Vault,
};
use zeroize::Zeroizing;

#[test]
fn default_directory_is_separate_for_native_test_builds() {
    let directory = totp_cli::store::default_directory().unwrap();
    let expected = if cfg!(feature = "native-test") {
        "local-totp-cli-rs-native-test"
    } else {
        "local-totp-cli-rs"
    };
    assert_eq!(directory.file_name().unwrap(), expected);
}

#[test]
fn roundtrip_metadata_never_contains_secret() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("Work", &enrollment()).unwrap();
    assert_eq!(
        store.get("work").unwrap().code_at(59.0).unwrap().0,
        "94287082"
    );
    let content = fs::read_to_string(directory.path().join("accounts.json")).unwrap();
    assert!(!content.contains(SECRET));
    assert!(!content.contains("\"secret\""));
    assert!(content.contains("local-totp-cli-rs"));
    let calls = vault.calls.load(Ordering::SeqCst);
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
    store.remove("WORK").unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(vault.secrets.lock().unwrap().is_empty());
}

#[test]
fn fresh_list_does_not_create_files_or_access_vault() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("missing");
    let vault = MemoryVault::default();
    let store = Store::new(missing.clone(), vault.clone());
    assert!(store.list().unwrap().is_empty());
    assert!(!missing.exists());
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn aliases_normalize_and_casefold_without_becoming_filenames() {
    let directory = tempdir().unwrap();
    let store = Store::new(directory.path().to_owned(), MemoryVault::default());
    for alias in ["Straße", "Cafe\u{301}", "公司", "CON"] {
        store.add(alias, &enrollment()).unwrap();
    }
    for alias in ["STRASSE", "CAFÉ", "公司", "con"] {
        assert!(store.get(alias).is_ok());
    }
    assert!(store.add("strasse", &enrollment()).is_err());
    assert!(store.add("café", &enrollment()).is_err());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn modern_unicode_aliases_match_their_lowercase_form() {
    let directory = tempdir().unwrap();
    let store = Store::new(directory.path().to_owned(), MemoryVault::default());
    store.add("Ა", &enrollment()).unwrap();
    assert!(store.get("ა").is_ok());
    store.remove("ა").unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn modern_unicode_aliases_cannot_be_duplicated() {
    let directory = tempdir().unwrap();
    let store = Store::new(directory.path().to_owned(), MemoryVault::default());
    store.add("Ა", &enrollment()).unwrap();
    assert!(store.add("ა", &enrollment()).is_err());
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn invalid_aliases_fail_before_writing() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    for alias in ["", "../work", "a/b", "-start", "a b", "a\n", "a\u{202e}"] {
        assert!(store.add(alias, &enrollment()).is_err());
    }
    assert!(store.add(&"a".repeat(65), &enrollment()).is_err());
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_index_commit_rolls_back_only_new_credential() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("old", &enrollment()).unwrap();
    let previous = fs::read(directory.path().join("accounts.json")).unwrap();
    let huge =
        Enrollment::new(SECRET, &"a".repeat(1024 * 1024), "", Algorithm::Sha1, 6, 30).unwrap();
    assert!(store.add("new", &huge).is_err());
    assert_eq!(
        fs::read(directory.path().join("accounts.json")).unwrap(),
        previous
    );
    assert_eq!(vault.secrets.lock().unwrap().len(), 1);
    assert!(store.get("old").is_ok());
}

#[test]
fn partial_vault_write_is_compensated_and_cleanup_failure_is_visible() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    vault.fail_put.store(true, Ordering::SeqCst);
    let store = Store::new(directory.path().to_owned(), vault.clone());
    assert!(store.add("work", &enrollment()).is_err());
    assert!(vault.secrets.lock().unwrap().is_empty());
    assert!(!directory.path().join("accounts.json").exists());
    vault.fail_delete.store(true, Ordering::SeqCst);
    let error = store.add("work", &enrollment()).unwrap_err().to_string();
    assert!(error.contains("cleanup"));
    assert!(!error.contains(SECRET));
}

#[test]
fn missing_credential_can_be_removed() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    vault.secrets.lock().unwrap().clear();
    assert!(store.get("work").is_err());
    store.remove("work").unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn corrupt_indices_and_python_format_are_not_overwritten() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    let index = directory.path().join("accounts.json");
    let invalid = [
        "SECRET_MARKER",
        "{\"version\":1,\"accounts\":[]}",
        "{\"format\":\"local-totp-cli-rs\",\"version\":1,\"version\":1,\"accounts\":[]}",
        "{\"format\":\"local-totp-cli-rs\",\"version\":2,\"accounts\":[]}",
        "{\"format\":\"local-totp-cli-rs\",\"version\":1,\"accounts\":[],\"secret\":\"SECRET_MARKER\"}",
    ];
    for content in invalid {
        fs::write(&index, content).unwrap();
        let error = store.add("work", &enrollment()).unwrap_err().to_string();
        assert!(!error.contains("SECRET_MARKER"));
        assert_eq!(fs::read_to_string(&index).unwrap(), content);
    }
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_ids_aliases_and_invalid_records_are_rejected() {
    let directory = tempdir().unwrap();
    let store = Store::new(directory.path().to_owned(), MemoryVault::default());
    store.add("work", &enrollment()).unwrap();
    let index = directory.path().join("accounts.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
    for (key, value) in [
        ("id", serde_json::json!("invalid")),
        ("period", serde_json::json!(0)),
        ("digits", serde_json::json!(7)),
        ("issuer", serde_json::json!("\u{202e}")),
        ("secret", serde_json::json!(SECRET)),
    ] {
        let mut document = original.clone();
        document["accounts"][0][key] = value;
        fs::write(&index, document.to_string()).unwrap();
        assert!(store.list().is_err());
    }
    for duplicate_id in [false, true] {
        let mut document = original.clone();
        let mut second = original["accounts"][0].clone();
        if duplicate_id {
            second["alias"] = serde_json::json!("different");
        } else {
            second["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
            second["alias"] = serde_json::json!("WORK");
        }
        document["accounts"].as_array_mut().unwrap().push(second);
        fs::write(&index, document.to_string()).unwrap();
        assert!(store.list().is_err());
    }
}

#[test]
fn oversized_valid_json_is_rejected_without_vault_access() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    let mut content = r#"{"format":"local-totp-cli-rs","version":1,"accounts":[]}"#.to_owned();
    content.push_str(&" ".repeat(1024 * 1024));
    fs::write(directory.path().join("accounts.json"), content).unwrap();
    assert!(store.list().is_err());
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_credential_deletion_preserves_the_index() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let store = Store::new(directory.path().to_owned(), vault.clone());
    store.add("work", &enrollment()).unwrap();
    let original = fs::read(directory.path().join("accounts.json")).unwrap();
    vault.fail_delete.store(true, Ordering::SeqCst);
    assert!(store.remove("work").is_err());
    assert_eq!(
        fs::read(directory.path().join("accounts.json")).unwrap(),
        original
    );
    assert_eq!(store.get("work").unwrap().secret(), SECRET);
}

#[test]
fn concurrent_imports_do_not_lose_accounts() {
    let directory = tempdir().unwrap();
    let store = Arc::new(Store::new(
        directory.path().to_owned(),
        MemoryVault::default(),
    ));
    std::thread::scope(|scope| {
        for index in 0..12 {
            let store = store.clone();
            scope.spawn(move || store.add(&format!("work{index}"), &enrollment()).unwrap());
        }
    });
    assert_eq!(store.list().unwrap().len(), 12);
}

#[test]
fn process_worker() {
    let Ok(directory) = std::env::var("TOTP_TEST_WORKER_DIR") else {
        return;
    };
    let alias = std::env::var("TOTP_TEST_WORKER_ALIAS").unwrap();
    Store::new(PathBuf::from(directory), MemoryVault::default())
        .add(&alias, &enrollment())
        .unwrap();
}

#[test]
fn independent_processes_do_not_lose_accounts() {
    let directory = tempdir().unwrap();
    let mut children = Vec::new();
    for index in 0..4 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process_worker"])
                .env("TOTP_TEST_WORKER_DIR", directory.path())
                .env("TOTP_TEST_WORKER_ALIAS", format!("process{index}"))
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(
        Store::new(directory.path().to_owned(), MemoryVault::default())
            .list()
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn contended_lock_times_out() {
    let directory = tempdir().unwrap();
    let lock = fs::File::create(directory.path().join("accounts.lock")).unwrap();
    fs2::FileExt::lock_exclusive(&lock).unwrap();
    let started = Instant::now();
    let error = Store::new(directory.path().to_owned(), MemoryVault::default())
        .add("work", &enrollment())
        .unwrap_err()
        .to_string();
    assert!(error.contains("updating"));
    assert!(started.elapsed().as_secs_f64() >= 4.9);
    assert!(started.elapsed().as_secs() < 15);
}

struct DeleteInterference {
    vault: MemoryVault,
    directory: PathBuf,
}

impl Vault for DeleteInterference {
    fn get(&self, id: &str) -> Result<Option<Zeroizing<String>>> {
        self.vault.get(id)
    }
    fn put(&self, id: &str, secret: &str) -> Result<()> {
        self.vault.put(id, secret)
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.vault.delete(id)?;
        fs::rename(
            self.directory.join("accounts.json"),
            self.directory.join("saved.json"),
        )
        .unwrap();
        fs::create_dir(self.directory.join("accounts.json")).unwrap();
        Ok(())
    }
}

#[test]
fn removal_can_be_retried_after_failed_index_commit() {
    let directory = tempdir().unwrap();
    let vault = MemoryVault::default();
    let ordinary = Store::new(directory.path().to_owned(), vault.clone());
    ordinary.add("work", &enrollment()).unwrap();
    let failing = Store::new(
        directory.path().to_owned(),
        DeleteInterference {
            vault,
            directory: directory.path().to_owned(),
        },
    );
    assert!(
        failing
            .remove("work")
            .unwrap_err()
            .to_string()
            .contains("Retry")
    );
    fs::remove_dir(directory.path().join("accounts.json")).unwrap();
    fs::rename(
        directory.path().join("saved.json"),
        directory.path().join("accounts.json"),
    )
    .unwrap();
    ordinary.remove("work").unwrap();
    assert!(ordinary.list().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn files_have_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempdir().unwrap();
    let data = directory.path().join("data");
    Store::new(data.clone(), MemoryVault::default())
        .add("work", &enrollment())
        .unwrap();
    assert_eq!(
        fs::metadata(&data).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for file in ["accounts.json", "accounts.lock"] {
        assert_eq!(
            fs::metadata(data.join(file)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
