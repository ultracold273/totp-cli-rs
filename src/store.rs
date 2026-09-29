use crate::enrollment::{Algorithm, Enrollment, validate_parameters, visible_text};
use crate::error::{AppError, Result};
use crate::password::{self, Password};
use crate::vault::{CredentialKind, SERVICE_PREFIX, Vault};
use icu_casemap::CaseMapper;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const NAMESPACE: &str = "local-totp-cli-rs";
const MAX_INDEX_BYTES: u64 = 1024 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<AccountType> {
    format: String,
    version: u32,
    accounts: Vec<AccountType>,
}

#[derive(Deserialize)]
struct DocumentVersion {
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAccount {
    id: String,
    alias: String,
    account: String,
    issuer: String,
    algorithm: Algorithm,
    digits: usize,
    period: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub alias: String,
    pub totp: Option<TotpMetadata>,
    pub password_id: Option<String>,
    #[serde(default)]
    pub pending_password_deletions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpMetadata {
    pub account: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub digits: usize,
    pub period: u64,
}

impl From<&Enrollment> for TotpMetadata {
    fn from(enrollment: &Enrollment) -> Self {
        Self {
            account: enrollment.account.clone(),
            issuer: enrollment.issuer.clone(),
            algorithm: enrollment.algorithm,
            digits: enrollment.digits,
            period: enrollment.period,
        }
    }
}

#[derive(Serialize)]
pub struct AccountSummary<'a> {
    id: &'a str,
    alias: &'a str,
    #[serde(flatten)]
    totp: Option<&'a TotpMetadata>,
    has_totp: bool,
    has_password: bool,
    password_cleanup_pending: bool,
}

impl Account {
    pub fn summary(&self) -> AccountSummary<'_> {
        AccountSummary {
            id: &self.id,
            alias: &self.alias,
            totp: self.totp.as_ref(),
            has_totp: self.totp.is_some(),
            has_password: self.password_id.is_some(),
            password_cleanup_pending: !self.pending_password_deletions.is_empty(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordGeneration {
    Generated,
    CleanupCompleted,
}

pub struct Store<V: Vault> {
    directory: PathBuf,
    vault: V,
}

impl<V: Vault> Store<V> {
    pub fn new(directory: PathBuf, vault: V) -> Self {
        Self { directory, vault }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn list(&self) -> Result<Vec<Account>> {
        if !self.exists()? {
            return Ok(Vec::new());
        }
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        accounts.sort_by_key(|account| folded(&account.alias));
        Ok(accounts)
    }

    pub fn add(&self, alias: &str, enrollment: &Enrollment) -> Result<()> {
        let alias = validate_alias(alias)?;
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        if accounts
            .iter()
            .any(|account| folded(&account.alias) == folded(&alias))
        {
            return Err(AppError::new(
                "That alias already exists. Nothing was replaced.",
            ));
        }
        let id = new_id()?;
        let record = Account {
            id: id.clone(),
            alias,
            totp: Some(TotpMetadata::from(enrollment)),
            password_id: None,
            pending_password_deletions: Vec::new(),
        };
        validate_record(&record)?;
        accounts.push(record);
        self.save_totp(&accounts, &id, enrollment)
    }

    pub fn enroll(&self, alias: &str, enrollment: &Enrollment) -> Result<()> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        let position = accounts
            .iter()
            .position(|record| folded(&record.alias) == folded(&alias))
            .ok_or_else(not_found)?;
        if accounts[position].totp.is_some() {
            return Err(AppError::new(
                "This account already has a TOTP enrollment. Nothing was replaced.",
            ));
        }
        accounts[position].totp = Some(TotpMetadata::from(enrollment));
        validate_record(&accounts[position])?;
        self.save_totp(&accounts, &accounts[position].id, enrollment)
    }

    fn save_totp(&self, accounts: &[Account], id: &str, enrollment: &Enrollment) -> Result<()> {
        let result = self
            .vault
            .put(CredentialKind::Totp, id, enrollment.secret())
            .map_err(|_| AppError::new("Could not save the credential to the OS credential store."))
            .and_then(|()| self.write(accounts));
        if let Err(error) = result {
            if self.vault.delete(CredentialKind::Totp, id).is_err() {
                return Err(AppError::new(format!(
                    "Import failed and credential cleanup failed. Remove the OS credential with ID {id}."
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn get(&self, alias: &str) -> Result<Enrollment> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let accounts = self.read()?;
        let record = find(&accounts, &alias)?;
        let totp = record
            .totp
            .as_ref()
            .ok_or_else(|| AppError::new("This account has no TOTP enrollment."))?;
        let secret = self.vault.get(CredentialKind::Totp, &record.id)
            .map_err(|_| AppError::new("Could not read the credential. Unlock the OS credential store."))?
            .ok_or_else(|| AppError::new("This account's credential is missing. Remove its index entry and import the enrollment again."))?;
        Enrollment::new(
            &secret,
            &totp.account,
            &totp.issuer,
            totp.algorithm,
            totp.digits,
            totp.period,
        )
    }

    pub fn generate_password(
        &self,
        alias: &str,
        length: usize,
        replace: bool,
    ) -> Result<PasswordGeneration> {
        let alias = validate_alias(alias)?;
        password::validate_length(length)?;
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        let position = accounts
            .iter()
            .position(|record| folded(&record.alias) == folded(&alias));
        if let Some(position) = position {
            if accounts[position].password_id.is_some() && !replace {
                return Err(AppError::new(
                    "This account already has a password. Use --replace to generate a replacement.",
                ));
            }
            if !accounts[position].pending_password_deletions.is_empty() {
                let resume_replacement = accounts[position].password_id.is_some();
                self.cleanup_passwords(&mut accounts, position)?;
                if resume_replacement {
                    // Retrying a committed change must not rotate the password again.
                    return Ok(PasswordGeneration::CleanupCompleted);
                }
            }
        }
        let password = password::generate(length)?;
        let position = match position {
            Some(position) => position,
            None => {
                accounts.push(Account {
                    id: new_id()?,
                    alias,
                    totp: None,
                    password_id: None,
                    pending_password_deletions: Vec::new(),
                });
                accounts.len() - 1
            }
        };
        let id = new_id()?;
        if let Some(previous) = accounts[position].password_id.replace(id.clone()) {
            accounts[position].pending_password_deletions.push(previous);
        }
        // Keep the previous credential until the new reference is durably committed.
        let result = self
            .vault
            .put(CredentialKind::Password, &id, password.as_str())
            .map_err(|_| {
                AppError::new("Could not save the generated password to the OS credential store.")
            })
            .and_then(|()| self.write(&accounts));
        if let Err(error) = result {
            if self.vault.delete(CredentialKind::Password, &id).is_err() {
                return Err(AppError::new(format!(
                    "Password generation failed and credential cleanup failed. The previous password reference is unchanged. Remove the password credential with ID {id}."
                )));
            }
            return Err(error);
        }
        self.cleanup_passwords(&mut accounts, position)?;
        Ok(PasswordGeneration::Generated)
    }

    pub fn get_password(&self, alias: &str) -> Result<Password> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let accounts = self.read()?;
        let record = find(&accounts, &alias)?;
        let id = record.password_id.as_ref().ok_or_else(no_password)?;
        let password = self
            .vault
            .get(CredentialKind::Password, id)
            .map_err(|_| AppError::new("Could not read the password. Unlock the OS credential store."))?
            .ok_or_else(|| {
                AppError::new(
                    "This account's password credential is missing. Generate a replacement with --replace.",
                )
            })?;
        Password::from_stored(password)
    }

    pub fn remove_password(&self, alias: &str) -> Result<()> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        let position = accounts
            .iter()
            .position(|record| folded(&record.alias) == folded(&alias))
            .ok_or_else(not_found)?;
        if let Some(id) = accounts[position].password_id.take() {
            accounts[position].pending_password_deletions.push(id);
            self.write(&accounts)?;
        } else if accounts[position].pending_password_deletions.is_empty() {
            return Err(no_password());
        }
        self.cleanup_passwords(&mut accounts, position)
    }

    fn cleanup_passwords(&self, accounts: &mut [Account], position: usize) -> Result<()> {
        if accounts[position].pending_password_deletions.is_empty() {
            return Ok(());
        }
        let has_password = accounts[position].password_id.is_some();
        for id in &accounts[position].pending_password_deletions {
            self.vault
                .delete(CredentialKind::Password, id)
                .map_err(|_| password_cleanup_error(has_password))?;
        }
        accounts[position].pending_password_deletions.clear();
        self.write(accounts)
            .map_err(|_| password_cleanup_error(has_password))
    }

    pub fn remove(&self, alias: &str) -> Result<()> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        let record = find(&accounts, &alias)?;
        for id in record
            .password_id
            .iter()
            .chain(&record.pending_password_deletions)
        {
            self.vault.delete(CredentialKind::Password, id).map_err(|_| {
                AppError::new("Could not remove all account credentials. Some may already be removed. Retry the remove command to finish cleanup.")
            })?;
        }
        if record.totp.is_some() {
            self.vault.delete(CredentialKind::Totp, &record.id).map_err(|_| {
                AppError::new("Could not remove all account credentials. Some may already be removed. Retry the remove command to finish cleanup.")
            })?;
        }
        let id = record.id.clone();
        accounts.retain(|account| account.id != id);
        self.write(&accounts).map_err(|_| AppError::new("The credential was removed but its index could not be updated. Retry the remove command to finish cleanup."))
    }

    fn exists(&self) -> Result<bool> {
        self.directory.try_exists().map_err(|_| directory_error())
    }

    fn lock(&self) -> Result<File> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&self.directory)
            .map_err(|_| directory_error())?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(self.directory.join("accounts.lock"))
            .map_err(|_| directory_error())?;
        let started = Instant::now();
        loop {
            match fs2::FileExt::try_lock_exclusive(&lock) {
                Ok(()) => return Ok(lock),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(AppError::new(
                            "Another TOTP process is updating the account index. Try again.",
                        ));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return Err(directory_error()),
            }
        }
    }

    fn read(&self) -> Result<Vec<Account>> {
        let file = match File::open(self.directory.join("accounts.json")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(AppError::new(
                    "Could not read the account index. Check its permissions.",
                ));
            }
        };
        let mut content = Vec::new();
        file.take(MAX_INDEX_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|_| invalid_index())?;
        if content.len() as u64 > MAX_INDEX_BYTES {
            return Err(invalid_index());
        }
        let header: DocumentVersion =
            serde_json::from_slice(&content).map_err(|_| invalid_index())?;
        let accounts = match header.version {
            1 => {
                let document: Document<LegacyAccount> =
                    serde_json::from_slice(&content).map_err(|_| invalid_index())?;
                if document.format != NAMESPACE || document.version != 1 {
                    return Err(invalid_index());
                }
                document
                    .accounts
                    .into_iter()
                    .map(|record| Account {
                        id: record.id,
                        alias: record.alias,
                        totp: Some(TotpMetadata {
                            account: record.account,
                            issuer: record.issuer,
                            algorithm: record.algorithm,
                            digits: record.digits,
                            period: record.period,
                        }),
                        password_id: None,
                        pending_password_deletions: Vec::new(),
                    })
                    .collect()
            }
            2 => {
                let document: Document<Account> =
                    serde_json::from_slice(&content).map_err(|_| invalid_index())?;
                if document.format != NAMESPACE || document.version != 2 {
                    return Err(invalid_index());
                }
                document.accounts
            }
            _ => return Err(invalid_index()),
        };
        let mut aliases = HashSet::new();
        let mut ids = HashSet::new();
        for record in &accounts {
            validate_record(record).map_err(|_| invalid_index())?;
            if !aliases.insert(folded(&record.alias)) || !ids.insert(&record.id) {
                return Err(invalid_index());
            }
            for id in record
                .password_id
                .iter()
                .chain(&record.pending_password_deletions)
            {
                if !canonical_id(id) || !ids.insert(id) {
                    return Err(invalid_index());
                }
            }
        }
        Ok(accounts)
    }

    fn write(&self, accounts: &[Account]) -> Result<()> {
        let document = Document {
            format: NAMESPACE.to_owned(),
            version: 2,
            accounts: accounts.to_vec(),
        };
        let mut content = serde_json::to_vec_pretty(&document).map_err(|_| write_error())?;
        content.push(b'\n');
        if content.len() as u64 > MAX_INDEX_BYTES {
            return Err(AppError::new(
                "The account index has reached its size limit.",
            ));
        }
        let mut temporary = NamedTempFile::new_in(&self.directory).map_err(|_| write_error())?;
        temporary.write_all(&content).map_err(|_| write_error())?;
        temporary.as_file().sync_all().map_err(|_| write_error())?;
        temporary
            .persist(self.directory.join("accounts.json"))
            .map_err(|_| write_error())?;
        Ok(())
    }
}

pub fn default_directory() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|directory| directory.join(SERVICE_PREFIX))
        .ok_or_else(|| {
            AppError::new("Could not determine the user data directory. Specify --data-dir.")
        })
}

pub fn validate_alias(alias: &str) -> Result<String> {
    let alias: String = alias.nfc().collect();
    if !(1..=64).contains(&alias.chars().count())
        || !alias.chars().next().is_some_and(char::is_alphanumeric)
        || !alias
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(AppError::new(
            "Use an alias of 1-64 letters, numbers, dots, underscores or hyphens; start with a letter or number.",
        ));
    }
    Ok(alias)
}

fn folded(alias: &str) -> String {
    CaseMapper::new().fold_string(alias).into_owned()
}

fn validate_record(record: &Account) -> Result<()> {
    if validate_alias(&record.alias)? != record.alias || !canonical_id(&record.id) {
        return Err(invalid_index());
    }
    if let Some(totp) = &record.totp {
        if visible_text(&totp.account, false)? != totp.account
            || visible_text(&totp.issuer, true)? != totp.issuer
        {
            return Err(invalid_index());
        }
        validate_parameters(totp.digits, totp.period)?;
    }
    Ok(())
}

fn canonical_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id)
}

fn new_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        AppError::new("Could not obtain secure randomness for a credential identifier.")
    })?;
    Ok(uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string())
}

fn find<'accounts>(accounts: &'accounts [Account], alias: &str) -> Result<&'accounts Account> {
    let target = folded(alias);
    accounts
        .iter()
        .find(|account| folded(&account.alias) == target)
        .ok_or_else(not_found)
}

fn not_found() -> AppError {
    AppError::new("Account not found. Import a TOTP QR or use 'totp password generate NAME'.")
}
fn no_password() -> AppError {
    AppError::new("This account has no stored password. Use 'totp password generate NAME'.")
}
fn password_cleanup_error(has_password: bool) -> AppError {
    AppError::new(if has_password {
        "The generated password is saved, but previous credential cleanup is incomplete. Retry 'totp password generate NAME --replace' to finish cleanup without generating another password."
    } else {
        "Password removal is pending credential cleanup. Retry 'totp password remove NAME' to finish cleanup."
    })
}
fn directory_error() -> AppError {
    AppError::new("Could not access the account index directory. Check its permissions.")
}
fn invalid_index() -> AppError {
    AppError::new(
        "The account index is invalid or from an unsupported version. It has not been overwritten.",
    )
}
fn write_error() -> AppError {
    AppError::new("Could not save the account index. Check free space and permissions.")
}
