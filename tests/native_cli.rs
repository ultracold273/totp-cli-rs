use image::Luma;
use qrcode::QrCode;
use std::{
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::{TempDir, tempdir};
use totp_cli::enrollment::{Algorithm, Enrollment};
use uuid::Uuid;

struct Fixture {
    directory: TempDir,
    alias: String,
    binary: PathBuf,
}

impl Fixture {
    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(&self.binary)
            .arg("--data-dir")
            .arg(self.directory.path())
            .args(arguments)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::new(&self.binary)
            .arg("--data-dir")
            .arg(self.directory.path())
            .args(["remove", &self.alias])
            .output();
    }
}

#[test]
#[ignore = "creates and cleans up a disposable credential through the actual CLI"]
fn native_cli_roundtrip() {
    let binary = std::env::var_os("TOTP_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_totp")));
    let version = Command::new(&binary).arg("--version").output().unwrap();
    let expected = format!(
        "totp {} (native-test namespace)\n",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        version.status.success() && version.stdout == expected.as_bytes(),
        "Native CLI tests require a binary built with --features native-test."
    );
    let fixture = Fixture {
        directory: tempdir().unwrap(),
        alias: format!("test-{}", Uuid::new_v4()),
        binary,
    };
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let uri = format!("otpauth://totp/RFC:public-test?secret={secret}&issuer=RFC&digits=8");
    let image = fixture.directory.path().join("public-test.png");
    QrCode::new(uri.as_bytes())
        .unwrap()
        .render::<Luma<u8>>()
        .min_dimensions(300, 300)
        .build()
        .save(&image)
        .unwrap();
    let added = fixture.run(&["add", &fixture.alias, "--qr", image.to_str().unwrap()]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let duplicate = fixture.run(&["add", &fixture.alias, "--qr", image.to_str().unwrap()]);
    assert_eq!(duplicate.status.code(), Some(1));
    let listed = fixture.run(&["list", "--json"]);
    assert!(listed.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(metadata.as_array().unwrap().len(), 1);
    assert_eq!(metadata[0]["alias"], fixture.alias);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(secret));
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let generated = fixture.run(&["code", &fixture.alias]);
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(generated.stderr.is_empty());
    let output = String::from_utf8(generated.stdout).unwrap();
    assert_eq!(output.len(), 9);
    assert!(output.ends_with('\n'));
    assert!(output.trim().bytes().all(|byte| byte.is_ascii_digit()));
    let enrollment = Enrollment::new(secret, "public-test", "RFC", Algorithm::Sha1, 8, 30).unwrap();
    assert!(
        (before / 30..=after / 30).any(|counter| enrollment
            .code_at((counter * 30) as f64)
            .unwrap()
            .0
            == output.trim())
    );
    let removed = fixture.run(&["remove", &fixture.alias]);
    assert!(removed.status.success());
    let listed = fixture.run(&["list", "--json"]);
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim(), "[]");
    assert_eq!(
        fixture.run(&["code", &fixture.alias]).status.code(),
        Some(1)
    );
}
