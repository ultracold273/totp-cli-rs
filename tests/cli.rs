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
    for command in ["add", "list", "code", "remove", "doctor", "--data-dir"] {
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
