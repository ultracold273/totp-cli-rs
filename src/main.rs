fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(totp_cli::cli::main_entry())
}
