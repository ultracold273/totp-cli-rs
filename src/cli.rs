use crate::{
    enrollment::Enrollment,
    error::{AppError, Result},
    password,
    qr::read_enrollment,
    store::{PasswordGeneration, Store, default_directory},
    vault::{NativeVault, Vault},
};
use clap::{Parser, Subcommand, error::ErrorKind};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const VERSION: &str = if cfg!(feature = "native-test") {
    concat!(env!("CARGO_PKG_VERSION"), " (native-test namespace)")
} else {
    env!("CARGO_PKG_VERSION")
};

#[derive(Parser)]
#[command(
    name = "totp",
    bin_name = "totp",
    version = VERSION,
    about = "Offline TOTP and generated passwords with native OS credential storage"
)]
struct Arguments {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Directory for non-secret account metadata"
    )]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Import one TOTP enrollment from a local PNG/JPEG image")]
    Add {
        name: String,
        #[arg(long, value_name = "PATH")]
        qr: PathBuf,
    },
    #[command(about = "Attach TOTP to an existing account without replacing any credentials")]
    Enroll {
        name: String,
        #[arg(long, value_name = "PATH")]
        qr: PathBuf,
    },
    #[command(about = "List metadata without reading account secrets")]
    List {
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Print a current code, or watch codes in an interactive terminal")]
    Code {
        name: String,
        #[arg(long)]
        watch: bool,
    },
    #[command(about = "Generate, display, or remove locally stored passwords")]
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    #[command(about = "Remove an account and all its local credentials")]
    Remove { name: String },
    #[command(about = "Show platform, selected backend and metadata location")]
    Doctor,
}

#[derive(Subcommand)]
enum PasswordCommand {
    #[command(
        about = "Generate and save an alphanumeric password without displaying it",
        long_about = "Generate and save a password containing at least one uppercase letter, one lowercase letter, and one digit. Creates a password-only account for a new alias, or keeps the existing account's TOTP enrollment. The password is not displayed; use 'totp password show NAME' to reveal it."
    )]
    Generate {
        name: String,
        #[arg(
            long,
            default_value_t = password::DEFAULT_LENGTH,
            value_parser = parse_password_length,
            help = "Password length, from 12 to 1280 characters"
        )]
        length: usize,
        #[arg(
            long,
            help = "Replace an existing password, or finish its pending cleanup on retry"
        )]
        replace: bool,
    },
    #[command(
        about = "Print the stored password in plaintext",
        long_about = "Print the stored password and a newline to stdout. Terminal logging and output redirection can capture the password."
    )]
    Show { name: String },
    #[command(about = "Remove only the password; keep the account and any TOTP enrollment")]
    Remove { name: String },
}

fn parse_password_length(value: &str) -> Result<usize> {
    let length = value
        .parse()
        .map_err(|_| AppError::new("Password length must be a whole number."))?;
    password::validate_length(length)?;
    Ok(length)
}

pub fn main_entry() -> u8 {
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() { 0 } else { 1 };
        }
        Err(_) => {
            let _ = writeln!(
                io::stderr(),
                "Error: invalid arguments. Run 'totp --help' for usage."
            );
            return 2;
        }
    };
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&interrupted);
    let result = (|| {
        ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))
            .map_err(|_| AppError::new("Could not install the interrupt handler."))?;
        let directory = match arguments.data_dir {
            Some(directory) => directory,
            None => default_directory()?,
        };
        let store = Store::new(directory, NativeVault::new());
        let interactive = io::stdout().is_terminal() && io::stdin().is_terminal();
        run(
            arguments.command,
            &store,
            &mut io::stdout().lock(),
            interactive,
            &interrupted,
        )
    })();
    if interrupted.load(Ordering::SeqCst) {
        return 130;
    }
    match result {
        Ok(status) => status,
        Err(error) => {
            let _ = writeln!(io::stderr(), "Error: {error}");
            1
        }
    }
}

fn run<V: Vault>(
    command: Command,
    store: &Store<V>,
    output: &mut impl Write,
    interactive: bool,
    interrupted: &AtomicBool,
) -> Result<u8> {
    match command {
        Command::Add { name, qr } => {
            crate::store::validate_alias(&name)?;
            let enrollment = read_enrollment(&qr)?;
            store.add(&name, &enrollment)?;
            writeln!(
                output,
                "Account imported. Use 'totp code NAME' to generate a code."
            )
            .map_err(|_| output_error())?;
        }
        Command::Enroll { name, qr } => {
            crate::store::validate_alias(&name)?;
            let enrollment = read_enrollment(&qr)?;
            store.enroll(&name, &enrollment)?;
            writeln!(
                output,
                "TOTP enrollment attached. Existing passwords and website settings are unchanged."
            )
            .map_err(|_| output_error())?;
        }
        Command::List { json } => {
            let accounts = store.list()?;
            if json {
                let summaries: Vec<_> = accounts.iter().map(|account| account.summary()).collect();
                serde_json::to_writer_pretty(&mut *output, &summaries)
                    .map_err(|_| output_error())?;
                writeln!(output).map_err(|_| output_error())?;
            } else {
                for account in accounts {
                    if let Some(totp) = &account.totp {
                        write!(
                            output,
                            "{}\t{}\t{}\t{} {} digits {}s",
                            account.alias,
                            totp.issuer,
                            totp.account,
                            totp.algorithm,
                            totp.digits,
                            totp.period
                        )
                        .map_err(|_| output_error())?;
                    } else {
                        write!(output, "{}\tno TOTP", account.alias).map_err(|_| output_error())?;
                    }
                    let status = if account.password_id.is_some() {
                        "yes"
                    } else {
                        "no"
                    };
                    let cleanup = if account.pending_password_deletions.is_empty() {
                        ""
                    } else {
                        " (cleanup pending)"
                    };
                    writeln!(output, "\tpassword: {status}{cleanup}")
                        .map_err(|_| output_error())?;
                }
            }
        }
        Command::Code { name, watch } => {
            if watch && !interactive {
                return Err(AppError::new(
                    "Watch mode requires an interactive terminal.",
                ));
            }
            let enrollment = store.get(&name)?;
            if watch {
                watch_loop(
                    &enrollment,
                    output,
                    now,
                    || interrupted.load(Ordering::SeqCst),
                    || thread::sleep(Duration::from_millis(200)),
                )?;
                return Ok(130);
            }
            writeln!(output, "{}", enrollment.code_at(now()?)?.0).map_err(|_| output_error())?;
        }
        Command::Password { command } => match command {
            PasswordCommand::Generate {
                name,
                length,
                replace,
            } => {
                let message = match store.generate_password(&name, length, replace)? {
                    PasswordGeneration::Generated => {
                        "Password generated and saved. Use 'totp password show NAME' to display it. Website passwords are unchanged."
                    }
                    PasswordGeneration::CleanupCompleted => {
                        "Previous password change cleanup completed. No new password was generated."
                    }
                };
                writeln!(output, "{message}").map_err(|_| output_error())?;
            }
            PasswordCommand::Show { name } => {
                let password = store.get_password(&name)?;
                writeln!(output, "{}", password.as_str()).map_err(|_| output_error())?;
            }
            PasswordCommand::Remove { name } => {
                store.remove_password(&name)?;
                writeln!(output, "Local password removed. Account metadata, TOTP enrollment, and website passwords are unchanged.")
                    .map_err(|_| output_error())?;
            }
        },
        Command::Remove { name } => {
            store.remove(&name)?;
            writeln!(
                output,
                "Local account and credentials removed. Website passwords and two-factor settings are unchanged."
            )
            .map_err(|_| output_error())?;
        }
        Command::Doctor => {
            let accounts = store.list()?;
            let pending: usize = accounts
                .iter()
                .map(|account| account.pending_password_deletions.len())
                .sum();
            writeln!(output, "Platform: {}\nSelected backend: {}\nCredential availability: not tested (no read/write probe)\nIndex: {}\nAccounts: {}\nPending password credential deletions: {}",
                std::env::consts::OS, NativeVault::label(), store.directory().join("accounts.json").display(), accounts.len(), pending).map_err(|_| output_error())?;
        }
    }
    output.flush().map_err(|_| output_error())?;
    Ok(0)
}

fn now() -> Result<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| AppError::new("The system clock must be set after the Unix epoch."))
}

fn output_error() -> AppError {
    AppError::new("Could not write to standard output.")
}

fn watch_loop(
    enrollment: &Enrollment,
    output: &mut impl Write,
    mut clock: impl FnMut() -> Result<f64>,
    mut stopped: impl FnMut() -> bool,
    mut wait: impl FnMut(),
) -> Result<()> {
    let result = (|| {
        while !stopped() {
            let (code, remaining) = enrollment.code_at(clock()?)?;
            write!(output, "\r{code}  {remaining:5}s remaining").map_err(|_| output_error())?;
            output.flush().map_err(|_| output_error())?;
            wait();
        }
        Ok(())
    })();
    let cleanup = write!(output, "\r{:40}\r", "")
        .and_then(|()| output.flush())
        .map_err(|_| output_error());
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::Algorithm;
    use std::cell::Cell;

    fn enrollment() -> Enrollment {
        Enrollment::new(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "work",
            "",
            Algorithm::Sha1,
            8,
            30,
        )
        .unwrap()
    }

    #[test]
    fn watch_refreshes_and_clears_on_interrupt() {
        let enrollment = enrollment();
        let frames = Cell::new(0);
        let mut output = Vec::new();
        watch_loop(
            &enrollment,
            &mut output,
            || Ok(if frames.get() == 0 { 29.2 } else { 30.0 }),
            || frames.get() == 2,
            || frames.set(frames.get() + 1),
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&enrollment.code_at(29.2).unwrap().0));
        assert!(output.contains(&enrollment.code_at(30.0).unwrap().0));
        assert!(output.contains("remaining"));
        assert!(output.ends_with(&format!("\r{}\r", " ".repeat(40))));
        assert!(!output.contains(enrollment.secret()));
    }

    #[test]
    fn watch_clock_failure_clears_output_without_panicking() {
        let mut output = Vec::new();
        assert!(
            watch_loop(
                &enrollment(),
                &mut output,
                || Err(AppError::new("Clock unavailable")),
                || false,
                || {}
            )
            .is_err()
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("\r{}\r", " ".repeat(40))
        );
    }
}
