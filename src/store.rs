use crate::enrollment::{Algorithm, Enrollment, validate_parameters, visible_text};
use crate::error::{AppError, Result};
use crate::vault::{SERVICE_PREFIX, Vault};
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
struct Document {
    format: String,
    version: u32,
    accounts: Vec<Account>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub alias: String,
    pub account: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub digits: usize,
    pub period: u64,
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
        let id = Uuid::new_v4().to_string();
        let record = Account {
            id: id.clone(),
            alias,
            account: enrollment.account.clone(),
            issuer: enrollment.issuer.clone(),
            algorithm: enrollment.algorithm,
            digits: enrollment.digits,
            period: enrollment.period,
        };
        validate_record(&record)?;
        accounts.push(record);
        let result = self
            .vault
            .put(&id, enrollment.secret())
            .map_err(|_| AppError::new("Could not save the credential to the OS credential store."))
            .and_then(|()| self.write(&accounts));
        if let Err(error) = result {
            if self.vault.delete(&id).is_err() {
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
        let secret = self.vault.get(&record.id)
            .map_err(|_| AppError::new("Could not read the credential. Unlock the OS credential store."))?
            .ok_or_else(|| AppError::new("This account's credential is missing. Remove its index entry and import the enrollment again."))?;
        Enrollment::new(
            &secret,
            &record.account,
            &record.issuer,
            record.algorithm,
            record.digits,
            record.period,
        )
    }

    pub fn remove(&self, alias: &str) -> Result<()> {
        let alias = validate_alias(alias)?;
        if !self.exists()? {
            return Err(not_found());
        }
        let _lock = self.lock()?;
        let mut accounts = self.read()?;
        let id = find(&accounts, &alias)?.id.clone();
        self.vault.delete(&id).map_err(|_| {
            AppError::new("Could not remove the credential from the OS credential store.")
        })?;
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
        let document: Document = serde_json::from_slice(&content).map_err(|_| invalid_index())?;
        if document.format != NAMESPACE || document.version != 1 {
            return Err(invalid_index());
        }
        let mut aliases = HashSet::new();
        let mut ids = HashSet::new();
        for record in &document.accounts {
            validate_record(record).map_err(|_| invalid_index())?;
            if !aliases.insert(folded(&record.alias)) || !ids.insert(&record.id) {
                return Err(invalid_index());
            }
        }
        Ok(document.accounts)
    }

    fn write(&self, accounts: &[Account]) -> Result<()> {
        let document = Document {
            format: NAMESPACE.to_owned(),
            version: 1,
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
    if validate_alias(&record.alias)? != record.alias
        || visible_text(&record.account, false)? != record.account
        || visible_text(&record.issuer, true)? != record.issuer
        || Uuid::parse_str(&record.id)
            .map_err(|_| invalid_index())?
            .to_string()
            != record.id
    {
        return Err(invalid_index());
    }
    validate_parameters(record.digits, record.period)
}

fn find<'accounts>(accounts: &'accounts [Account], alias: &str) -> Result<&'accounts Account> {
    let target = folded(alias);
    accounts
        .iter()
        .find(|account| folded(&account.alias) == target)
        .ok_or_else(not_found)
}

fn not_found() -> AppError {
    AppError::new("Account not found. Import it with 'totp add NAME --qr PATH'.")
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
