use data_encoding::BASE32_NOPAD;
use totp_cli::enrollment::{Algorithm, Enrollment, parse_enrollment};

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn parses_and_generates_rfc_code() {
    let enrollment =
        parse_enrollment(&format!("otpauth://totp/work?secret={SECRET}&digits=8")).unwrap();
    assert_eq!(enrollment.code_at(59.0).unwrap(), ("94287082".into(), 1));
}

#[test]
fn all_eighteen_rfc_vectors() {
    let vectors = [
        (59.0, ["94287082", "46119246", "90693936"]),
        (1111111109.0, ["07081804", "68084774", "25091201"]),
        (1111111111.0, ["14050471", "67062674", "99943326"]),
        (1234567890.0, ["89005924", "91819424", "93441116"]),
        (2000000000.0, ["69279037", "90698825", "38618901"]),
        (20000000000.0, ["65353130", "77737706", "47863826"]),
    ];
    let seed = b"1234567890123456789012345678901234567890123456789012345678901234";
    for (index, (algorithm, length)) in [
        (Algorithm::Sha1, 20),
        (Algorithm::Sha256, 32),
        (Algorithm::Sha512, 64),
    ]
    .into_iter()
    .enumerate()
    {
        let enrollment = Enrollment::new(
            &BASE32_NOPAD.encode(&seed[..length]),
            "work",
            "",
            algorithm,
            8,
            30,
        )
        .unwrap();
        for (timestamp, expected) in vectors {
            assert_eq!(enrollment.code_at(timestamp).unwrap().0, expected[index]);
        }
    }
}

#[test]
fn defaults_unicode_and_redacted_debug() {
    let enrollment = parse_enrollment("otpauth://totp/%E5%85%AC%E5%8F%B8:alice%2Bwork?secret=jbswy3dpehpk3pxp&issuer=%E5%85%AC%E5%8F%B8").unwrap();
    assert_eq!(enrollment.account, "alice+work");
    assert_eq!(enrollment.issuer, "公司");
    assert_eq!(enrollment.secret(), "JBSWY3DPEHPK3PXP");
    assert_eq!(
        (enrollment.algorithm, enrollment.digits, enrollment.period),
        (Algorithm::Sha1, 6, 30)
    );
    assert!(!format!("{enrollment:?}").contains(enrollment.secret()));
}

#[test]
fn issuer_parameter_takes_precedence_over_label_prefix() {
    let enrollment = parse_enrollment(&format!(
        "otpauth://totp/Example:alice%2Bwork?secret={SECRET}&issuer=example.com&algorithm=SHA256&digits=8&period=60"
    ))
    .unwrap();
    assert_eq!(enrollment.account, "alice+work");
    assert_eq!(enrollment.issuer, "example.com");
    assert_eq!(enrollment.secret(), SECRET);
    assert_eq!(
        (enrollment.algorithm, enrollment.digits, enrollment.period),
        (Algorithm::Sha256, 8, 60)
    );
    let expected = Enrollment::new(SECRET, "alice+work", "", Algorithm::Sha256, 8, 60).unwrap();
    assert_eq!(
        enrollment.code_at(59.0).unwrap(),
        expected.code_at(59.0).unwrap()
    );
}

#[test]
fn issuer_uses_label_prefix_when_parameter_is_missing_or_blank() {
    for suffix in ["", "&issuer=", "&issuer=%20"] {
        let enrollment = parse_enrollment(&format!(
            "otpauth://totp/Acme:alice?secret={SECRET}{suffix}"
        ))
        .unwrap();
        assert_eq!(enrollment.issuer, "Acme");
        assert_eq!(enrollment.account, "alice");
    }
}

#[test]
fn issuer_does_not_require_a_label_prefix() {
    for (suffix, expected) in [("&issuer=example.com", "example.com"), ("", "")] {
        let enrollment =
            parse_enrollment(&format!("otpauth://totp/alice?secret={SECRET}{suffix}")).unwrap();
        assert_eq!(enrollment.issuer, expected);
        assert_eq!(enrollment.account, "alice");
    }
}

#[test]
fn time_boundaries_and_short_valid_secrets() {
    let enrollment = Enrollment::new("MY======", "work", "", Algorithm::Sha1, 6, 60).unwrap();
    assert_eq!(enrollment.secret(), "MY");
    assert_eq!(enrollment.code_at(0.0).unwrap().1, 60);
    assert_eq!(enrollment.code_at(59.2).unwrap().1, 1);
    assert_eq!(enrollment.code_at(60.0).unwrap().1, 60);
    assert_eq!(
        enrollment.code_at(59.2).unwrap().0,
        enrollment.code_at(59.9).unwrap().0
    );
}

#[test]
fn invalid_clock_is_rejected() {
    let enrollment = Enrollment::new(SECRET, "work", "", Algorithm::Sha1, 6, 30).unwrap();
    for timestamp in [
        -1.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        u64::MAX as f64,
    ] {
        assert!(enrollment.code_at(timestamp).is_err());
    }
}

#[test]
fn invalid_base32_is_rejected_without_echoing() {
    for secret in [
        "",
        "A",
        "MZ",
        "MZX",
        "MY=",
        "M=Y=====",
        "ABCD0EFG",
        "MY====== ",
        "MY=======",
    ] {
        assert!(
            Enrollment::new(secret, "work", "", Algorithm::Sha1, 6, 30).is_err(),
            "unexpected secret accepted"
        );
    }
}

#[test]
fn invalid_uri_is_rejected_without_echoing() {
    let cases = [
        "https://totp/work?secret=SECRET_MARKER",
        "otpauth://hotp/work?secret=SECRET_MARKER",
        "otpauth://totp/work?secret=SECRET_MARKER&secret=OTHER",
        "otpauth://totp/work?secret=SECRET_MARKER&extra=1",
        "otpauth://totp/work?secret=SECRET_MARKER#fragment",
        "otpauth://totp/?secret=SECRET_MARKER",
        "otpauth://totp/work?secret=SECRET_MARKER&digits=7",
        "otpauth://totp/work?secret=SECRET_MARKER&period=0",
        "otpauth://totp/work?secret=SECRET_MARKER&period=86401",
        "otpauth://totp/work?secret=SECRET_MARKER&period=+30",
        "otpauth://totp/work?secret=SECRET_MARKER&algorithm=MD5",
        "otpauth://totp/work%ZZ?secret=SECRET_MARKER",
        "otpauth://totp/work%FF?secret=SECRET_MARKER",
        "otpauth://totp/work%0A?secret=SECRET_MARKER",
        "otpauth://totp/work?secret=SECRET_MARKER&",
        "otpauth://totp/work?secret=SECRET_MARKER&issuer",
        "otpauth://totp/work\n?secret=SECRET_MARKER",
        "otpauth://totp/work?secret=SECRET_MARKER&issuer=%E2%80%AE",
        "otpauth://totp/work?issuer=SECRET_MARKER",
    ];
    for uri in cases {
        let uri = uri.replace("SECRET_MARKER", SECRET);
        let error = parse_enrollment(&uri).unwrap_err();
        for output in [error.to_string(), format!("{error:?}")] {
            assert!(!output.contains(SECRET));
            assert!(!output.contains(&uri));
        }
    }
}

#[test]
fn invalid_issuer_and_label_components_are_rejected() {
    for label_and_query in [
        "Acme:alice:extra?secret=MY",
        "Acme:alice:extra?secret=MY&issuer=other",
        "Acme%00:alice?secret=MY&issuer=other",
        "Acme%ZZ:alice?secret=MY&issuer=other",
        "Acme:?secret=MY&issuer=other",
        "alice?secret=MY&issuer=Acme%3AOps",
        "Acme:alice?secret=MY&issuer=%00",
        "Acme:alice?secret=MY&issuer=other&issuer=another",
        "Acme:alice?secret=MY&issuer=other&issuer=other",
    ] {
        assert!(parse_enrollment(&format!("otpauth://totp/{label_and_query}")).is_err());
    }
}

#[test]
fn rejects_valid_secret_with_invalid_options() {
    for suffix in [
        "&digits=7",
        "&digits=06",
        "&period=0",
        "&period=86401",
        "&period=+30",
        "&algorithm=MD5",
        "&issuer=%00",
        "&secret=MY",
        "&unknown=x",
        "&",
        "#",
    ] {
        assert!(
            parse_enrollment(&format!("otpauth://totp/work?secret={SECRET}{suffix}")).is_err(),
            "accepted {suffix}"
        );
    }
    assert!(
        parse_enrollment(&format!(
            "otpauth://totp/{}?secret={SECRET}",
            "a".repeat(8192)
        ))
        .is_err()
    );
}
