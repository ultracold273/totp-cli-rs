use std::{
    fs,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_totp"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn help_and_version_do_not_open_the_vault() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    for command in [
        "add",
        "enroll",
        "list",
        "code",
        "password",
        "remove",
        "doctor",
        "--data-dir",
    ] {
        assert!(text.contains(command));
    }
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn password_help_documents_defaults_and_plaintext_output() {
    let help = run(&["password", "generate", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--replace"));
    assert!(text.contains("--length"));
    assert!(text.contains("default: 12"));
    assert!(text.contains("1280"));
    assert!(text.contains("uppercase"));
    assert!(text.contains("lowercase"));
    assert!(text.contains("digit"));
    let help = run(&["password", "show", "--help"]);
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("Terminal logging")
    );
}

#[test]
fn password_arguments_reject_imports_and_invalid_lengths_without_side_effects() {
    let temporary = tempdir().unwrap();
    let directory = temporary.path().join("missing");
    for arguments in [
        vec!["password", "set", "work", "SECRET_MARKER"],
        vec!["password", "generate", "work", "--stdin"],
        vec![
            "password",
            "generate",
            "work",
            "--password",
            "SECRET_MARKER",
        ],
        vec!["password", "generate", "work", "--length", "11"],
        vec!["password", "generate", "work", "--length", "1281"],
        vec!["password", "generate", "work", "--length", "SECRET_MARKER"],
        vec!["password", "show"],
    ] {
        let mut args = vec!["--data-dir", directory.to_str().unwrap()];
        args.extend(arguments);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(
            !String::from_utf8(result.stderr)
                .unwrap()
                .contains("SECRET_MARKER")
        );
        assert!(!directory.exists());
    }
}

#[test]
fn missing_password_operations_fail_without_creating_an_index() {
    let temporary = tempdir().unwrap();
    let directory = temporary.path().join("missing");
    for command in ["show", "remove"] {
        let result = run(&[
            "--data-dir",
            directory.to_str().unwrap(),
            "password",
            command,
            "missing",
        ]);
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert!(
            String::from_utf8(result.stderr)
                .unwrap()
                .contains("not found")
        );
        assert!(!directory.exists());
    }
}

#[test]
fn version_two_metadata_lists_without_secret_reads_or_legacy_totp_placeholders() {
    let temporary = tempdir().unwrap();
    let metadata = r#"{"format":"local-totp-cli-rs","version":2,"accounts":[{"id":"74946511-8151-43b2-bf2e-83591d7480f2","alias":"work","totp":null,"password_id":"550e8400-e29b-41d4-a716-446655440000","pending_password_deletions":[]}]}"#;
    fs::write(temporary.path().join("accounts.json"), metadata).unwrap();
    let listed = run(&[
        "--data-dir",
        temporary.path().to_str().unwrap(),
        "list",
        "--json",
    ]);
    assert!(listed.status.success());
    let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(value[0]["has_password"], true);
    assert_eq!(value[0]["has_totp"], false);
    assert!(value[0].get("password_id").is_none());
    assert!(value[0].get("algorithm").is_none());
    let code = run(&[
        "--data-dir",
        temporary.path().to_str().unwrap(),
        "code",
        "work",
    ]);
    assert_eq!(code.status.code(), Some(1));
    assert!(code.stdout.is_empty());
    assert!(String::from_utf8(code.stderr).unwrap().contains("no TOTP"));
    assert_eq!(
        fs::read_to_string(temporary.path().join("accounts.json")).unwrap(),
        metadata
    );
}

#[test]
fn version_marks_the_native_test_namespace_only_when_enabled() {
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout)
            .unwrap()
            .contains("(native-test namespace)"),
        cfg!(feature = "native-test")
    );
}

#[test]
fn argument_errors_do_not_echo_secrets() {
    for arguments in [
        vec!["SECRET_MARKER"],
        vec!["code", "--unknown", "SECRET_MARKER"],
        vec!["add", "work", "--qr"],
        vec![],
    ] {
        let result = run(&arguments);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(
            !String::from_utf8(result.stderr)
                .unwrap()
                .contains("SECRET_MARKER")
        );
    }
}

#[test]
fn empty_list_is_json_and_does_not_create_a_directory() {
    let temporary = tempdir().unwrap();
    let data = temporary.path().join("missing");
    let result = run(&["--data-dir", data.to_str().unwrap(), "list", "--json"]);
    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "[]");
    assert!(result.stderr.is_empty());
    assert!(!data.exists());
}

#[test]
fn metadata_listing_and_doctor_do_not_need_real_credentials() {
    let temporary = tempdir().unwrap();
    fs::write(temporary.path().join("accounts.json"), r#"{"format":"local-totp-cli-rs","version":1,"accounts":[{"id":"74946511-8151-43b2-bf2e-83591d7480f2","alias":"work","account":"alice","issuer":"Company","algorithm":"SHA1","digits":6,"period":30}]}"#).unwrap();
    for command in ["list", "doctor"] {
        let result = run(&["--data-dir", temporary.path().to_str().unwrap(), command]);
        assert!(result.status.success());
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(!output.is_empty());
        if command == "doctor" {
            assert!(output.contains("not tested"));
        } else {
            assert!(output.contains("alice"));
        }
    }
}

#[test]
fn missing_account_fails_on_stderr() {
    let temporary = tempdir().unwrap();
    let result = run(&[
        "--data-dir",
        temporary.path().to_str().unwrap(),
        "code",
        "missing",
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("not found")
    );
}

#[test]
fn watch_requires_an_interactive_terminal_before_reading_the_vault() {
    let temporary = tempdir().unwrap();
    let result = run(&[
        "--data-dir",
        temporary.path().to_str().unwrap(),
        "code",
        "missing",
        "--watch",
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("interactive terminal")
    );
}

#[test]
fn invalid_image_and_index_errors_are_sanitized() {
    let temporary = tempdir().unwrap();
    let image = temporary.path().join("invalid.png");
    fs::write(&image, "SECRET_MARKER").unwrap();
    let result = run(&[
        "--data-dir",
        temporary.path().to_str().unwrap(),
        "add",
        "work",
        "--qr",
        image.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(
        !String::from_utf8(result.stderr)
            .unwrap()
            .contains("SECRET_MARKER")
    );
    fs::write(temporary.path().join("accounts.json"), "SECRET_MARKER").unwrap();
    let result = run(&["--data-dir", temporary.path().to_str().unwrap(), "list"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(
        !String::from_utf8(result.stderr)
            .unwrap()
            .contains("SECRET_MARKER")
    );
}

#[test]
fn failed_password_storage_never_prints_a_password_or_success_message() {
    let temporary = tempdir().unwrap();
    let file = temporary.path().join("not-a-directory");
    fs::write(&file, b"unchanged").unwrap();
    let result = run(&[
        "--data-dir",
        file.to_str().unwrap(),
        "password",
        "generate",
        "work",
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("directory")
    );
    assert_eq!(fs::read(file).unwrap(), b"unchanged");
}
