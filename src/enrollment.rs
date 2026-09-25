use crate::error::{AppError, Result};
use data_encoding::{BASE32, BASE32_NOPAD};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use unicode_general_category::{GeneralCategory, get_general_category};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

pub struct Enrollment {
    secret: Zeroizing<String>,
    pub account: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub digits: usize,
    pub period: u64,
}

impl Enrollment {
    pub fn new(
        secret: &str,
        account: &str,
        issuer: &str,
        algorithm: Algorithm,
        digits: usize,
        period: u64,
    ) -> Result<Self> {
        validate_parameters(digits, period)?;
        Ok(Self {
            secret: normalize_secret(secret)?,
            account: visible_text(account, false)?,
            issuer: visible_text(issuer, true)?,
            algorithm,
            digits,
            period,
        })
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn code_at(&self, timestamp: f64) -> Result<(String, u64)> {
        validate_parameters(self.digits, self.period)?;
        if !timestamp.is_finite() || timestamp < 0.0 || timestamp >= u64::MAX as f64 {
            return Err(AppError::new(
                "The system clock is outside the supported Unix time range.",
            ));
        }
        let secret = BASE32_NOPAD
            .decode(self.secret.as_bytes())
            .map_err(|_| invalid_secret())?;
        let generator = totp_rs::Builder::new()
            .with_algorithm(match self.algorithm {
                Algorithm::Sha1 => totp_rs::Algorithm::SHA1,
                Algorithm::Sha256 => totp_rs::Algorithm::SHA256,
                Algorithm::Sha512 => totp_rs::Algorithm::SHA512,
            })
            .with_secret(secret)
            .with_digits(self.digits as u8)
            .with_step_duration(self.period)
            .build_noncompliant();
        let remaining = (self.period as f64 - timestamp % self.period as f64).ceil() as u64;
        Ok((
            generator.generate(timestamp.floor() as u64).to_string(),
            remaining,
        ))
    }
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Enrollment { sensitive contents redacted }")
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        })
    }
}

pub(crate) fn validate_parameters(digits: usize, period: u64) -> Result<()> {
    if !matches!(digits, 6 | 8) || !(1..=86400).contains(&period) {
        return Err(AppError::new(
            "Use 6 or 8 digits and a period from 1 to 86400 seconds.",
        ));
    }
    Ok(())
}

fn is_visible(character: char) -> bool {
    !matches!(
        get_general_category(character),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

pub(crate) fn visible_text(value: &str, allow_empty: bool) -> Result<String> {
    if !value.chars().all(is_visible)
        || value.contains(':')
        || (!allow_empty && value.trim().is_empty())
    {
        return Err(AppError::new(
            "The account or issuer contains invalid text.",
        ));
    }
    Ok(value.trim().to_owned())
}

fn invalid_secret() -> AppError {
    AppError::new("The enrollment secret is not valid canonical Base32.")
}

fn normalize_secret(value: &str) -> Result<Zeroizing<String>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || (b'2'..=b'7').contains(&byte) || byte == b'=')
    {
        return Err(invalid_secret());
    }
    let uppercase = Zeroizing::new(value.to_ascii_uppercase());
    let raw = uppercase.trim_end_matches('=');
    let decoded = Zeroizing::new(
        BASE32_NOPAD
            .decode(raw.as_bytes())
            .map_err(|_| invalid_secret())?,
    );
    if decoded.is_empty()
        || BASE32_NOPAD.encode(&decoded) != raw
        || (uppercase.contains('=') && BASE32.encode(&decoded) != *uppercase)
    {
        return Err(invalid_secret());
    }
    Ok(Zeroizing::new(raw.to_owned()))
}

fn invalid_uri() -> AppError {
    AppError::new("The QR payload is not a valid TOTP enrollment URI.")
}

fn decode_component(value: &str, query: bool) -> Result<Zeroizing<String>> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|value| (value as char).to_digit(16))
                    .ok_or_else(invalid_uri)?;
                let low = bytes
                    .next()
                    .and_then(|value| (value as char).to_digit(16))
                    .ok_or_else(invalid_uri)?;
                decoded.push((high * 16 + low) as u8);
            }
            b'+' if query => decoded.push(b' '),
            _ => decoded.push(byte),
        }
    }
    let text = std::str::from_utf8(&decoded).map_err(|_| invalid_uri())?;
    if !text.chars().all(is_visible) {
        return Err(invalid_uri());
    }
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn parse_enrollment(uri: &str) -> Result<Enrollment> {
    if uri.len() > 8192 || uri.contains('#') || !uri.chars().all(is_visible) {
        return Err(invalid_uri());
    }
    let body = uri.strip_prefix("otpauth://totp/").ok_or_else(|| AppError::new("Expected an otpauth://totp/ enrollment QR. HOTP, push, passkey and migration codes are unsupported."))?;
    let (label, query) = body.split_once('?').ok_or_else(invalid_uri)?;
    let label = decode_component(label, false)?;
    let mut options = BTreeMap::new();
    for (index, pair) in query.split('&').enumerate() {
        if index >= 16 {
            return Err(invalid_uri());
        }
        let (key, value) = pair.split_once('=').ok_or_else(invalid_uri)?;
        let key = decode_component(key, true)?;
        if !matches!(
            key.as_str(),
            "secret" | "issuer" | "algorithm" | "digits" | "period"
        ) {
            return Err(AppError::new(
                "The enrollment URI contains an unsupported parameter.",
            ));
        }
        if options
            .insert(key.to_string(), decode_component(value, true)?)
            .is_some()
        {
            return Err(AppError::new(
                "The enrollment URI contains a repeated parameter.",
            ));
        }
    }
    let option = |key: &str, fallback| {
        options
            .get(key)
            .map(|value| value.as_str())
            .unwrap_or(fallback)
    };
    let mut issuer = visible_text(option("issuer", ""), true)?;
    let account = if let Some((prefix, account)) = label.split_once(':') {
        let prefix = visible_text(prefix, false)?;
        if options.contains_key("issuer") && issuer != prefix {
            return Err(AppError::new(
                "The enrollment issuer and account-label prefix do not match.",
            ));
        }
        issuer = prefix;
        visible_text(account, false)?
    } else {
        visible_text(&label, false)?
    };
    let algorithm = match option("algorithm", "SHA1").to_ascii_uppercase().as_str() {
        "SHA1" => Algorithm::Sha1,
        "SHA256" => Algorithm::Sha256,
        "SHA512" => Algorithm::Sha512,
        _ => {
            return Err(AppError::new(
                "Supported algorithms are SHA1, SHA256 and SHA512.",
            ));
        }
    };
    let digits = match option("digits", "6") {
        "6" => 6,
        "8" => 8,
        _ => return Err(invalid_uri()),
    };
    let period = option("period", "30");
    if period.is_empty() || period.len() > 5 || !period.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_uri());
    }
    let period = period.parse().map_err(|_| invalid_uri())?;
    Enrollment::new(
        option("secret", ""),
        &account,
        &issuer,
        algorithm,
        digits,
        period,
    )
}
