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

const PUBLIC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

struct Fixture {
    directory: TempDir,
    alias: String,
    binary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
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
        Self {
            directory: tempdir().unwrap(),
            alias: format!("test-{}", Uuid::new_v4()),
            binary,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(&self.binary)
            .arg("--data-dir")
            .arg(self.directory.path())
            .args(arguments)
            .output()
            .unwrap()
    }

    fn enrollment_image(&self) -> PathBuf {
        let uri =
            format!("otpauth://totp/RFC:public-test?secret={PUBLIC_SECRET}&issuer=RFC&digits=8");
        let image = self.directory.path().join("public-test.png");
        QrCode::new(uri.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .min_dimensions(300, 300)
            .build()
            .save(&image)
            .unwrap();
        image
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
    let fixture = Fixture::new();
    let secret = PUBLIC_SECRET;
    let image = fixture.enrollment_image();
    let added = fixture.run(&["add", &fixture.alias, "--qr", image.to_str().unwrap()]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let duplicate = fixture.run(&["add", &fixture.alias, "--qr", image.to_str().unwrap()]);
    assert_eq!(duplicate.status.code(), Some(1));
    let saved_password = fixture.run(&["password", "generate", &fixture.alias]);
    assert!(
        saved_password.status.success(),
        "{}",
        String::from_utf8_lossy(&saved_password.stderr)
    );
    let shown = fixture.run(&["password", "show", &fixture.alias]);
    assert!(shown.status.success());
    let password = String::from_utf8(shown.stdout).unwrap();
    assert_eq!(password.len(), 13);
    assert!(!String::from_utf8_lossy(&saved_password.stdout).contains(password.trim_end()));
    let listed = fixture.run(&["list", "--json"]);
    assert!(listed.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(metadata.as_array().unwrap().len(), 1);
    assert_eq!(metadata[0]["alias"], fixture.alias);
    assert_eq!(metadata[0]["has_totp"], true);
    assert_eq!(metadata[0]["has_password"], true);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(password.trim_end()));
    let password_removed = fixture.run(&["password", "remove", &fixture.alias]);
    assert!(password_removed.status.success());
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

#[test]
#[ignore = "creates and cleans up disposable generated passwords through the actual CLI"]
fn native_cli_password_only_lifecycle() {
    let fixture = Fixture::new();
    let generated = fixture.run(&["password", "generate", &fixture.alias]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(generated.stderr.is_empty());
    let shown = fixture.run(&["password", "show", &fixture.alias]);
    assert!(shown.status.success());
    assert!(shown.stderr.is_empty());
    let original = String::from_utf8(shown.stdout).unwrap();
    assert_eq!(original.len(), 13);
    assert!(original.ends_with('\n'));
    let value = original.trim_end();
    assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(value.bytes().any(|byte| byte.is_ascii_uppercase()));
    assert!(value.bytes().any(|byte| byte.is_ascii_lowercase()));
    assert!(value.bytes().any(|byte| byte.is_ascii_digit()));
    assert!(!String::from_utf8_lossy(&generated.stdout).contains(value));
    assert!(
        !std::fs::read_to_string(fixture.directory.path().join("accounts.json"))
            .unwrap()
            .contains(value)
    );
    let refused = fixture.run(&["password", "generate", &fixture.alias]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty());
    assert!(fixture.run(&["password", "show", &fixture.alias]).stdout == original.as_bytes());
    let no_totp = fixture.run(&["code", &fixture.alias]);
    assert_eq!(no_totp.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&no_totp.stderr).contains("no TOTP"));

    for length in ["20", "1280"] {
        let replaced = fixture.run(&[
            "password",
            "generate",
            &fixture.alias,
            "--replace",
            "--length",
            length,
        ]);
        assert!(
            replaced.status.success(),
            "{}",
            String::from_utf8_lossy(&replaced.stderr)
        );
        let shown = fixture.run(&["password", "show", &fixture.alias]);
        assert!(shown.status.success());
        assert_eq!(shown.stdout.len(), length.parse::<usize>().unwrap() + 1);
        assert!(shown.stdout.ends_with(b"\n"));
    }
    let removed = fixture.run(&["password", "remove", &fixture.alias]);
    assert!(removed.status.success());
    let listed = fixture.run(&["list", "--json"]);
    assert!(listed.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(metadata.as_array().unwrap().len(), 1);
    assert_eq!(metadata[0]["has_totp"], false);
    assert_eq!(metadata[0]["has_password"], false);
    assert!(!metadata[0]["password_cleanup_pending"].as_bool().unwrap());
    assert_eq!(
        fixture
            .run(&["password", "show", &fixture.alias])
            .status
            .code(),
        Some(1)
    );
    assert!(
        fixture
            .run(&["password", "generate", &fixture.alias])
            .status
            .success()
    );
    let password = fixture.run(&["password", "show", &fixture.alias]).stdout;
    let image = fixture.enrollment_image();
    assert!(
        fixture
            .run(&["enroll", &fixture.alias, "--qr", image.to_str().unwrap()])
            .status
            .success()
    );
    assert!(fixture.run(&["password", "show", &fixture.alias]).stdout == password);
    assert!(fixture.run(&["code", &fixture.alias]).status.success());
    assert_eq!(
        fixture
            .run(&["enroll", &fixture.alias, "--qr", image.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    assert!(fixture.run(&["remove", &fixture.alias]).status.success());
    let listed = fixture.run(&["list", "--json"]);
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim(), "[]");
}
