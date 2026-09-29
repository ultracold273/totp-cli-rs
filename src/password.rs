use std::fmt;

use crate::error::{AppError, Result};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_LENGTH: usize = 12;
pub const MIN_LENGTH: usize = 12;
pub const MAX_LENGTH: usize = 1280;

const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub struct Password(Zeroizing<String>);

impl Password {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_stored(value: Zeroizing<String>) -> Result<Self> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&value.len())
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !has_required_classes(&value)
        {
            return Err(AppError::new("The stored password has invalid data."));
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password { sensitive contents redacted }")
    }
}

pub fn validate_length(length: usize) -> Result<()> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(AppError::new(
            "Password length must be from 12 to 1280 characters.",
        ));
    }
    Ok(())
}

pub fn generate(length: usize) -> Result<Password> {
    generate_with(length, |bytes| {
        getrandom::fill(bytes).map_err(|_| {
            AppError::new("Could not obtain secure randomness. No password was generated.")
        })
    })
}

fn has_required_classes(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
        && value.bytes().any(|byte| byte.is_ascii_digit())
}

fn generate_with(length: usize, mut fill: impl FnMut(&mut [u8]) -> Result<()>) -> Result<Password> {
    validate_length(length)?;
    let mut value = Zeroizing::new(String::with_capacity(length));
    let mut random = Zeroizing::new([0_u8; 64]);
    loop {
        value.zeroize();
        while value.len() < length {
            fill(random.as_mut())?;
            for &byte in random.iter() {
                // 248 is divisible by 62, so rejected bytes cannot bias the alphabet.
                if byte < 248 {
                    value.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
                    if value.len() == length {
                        break;
                    }
                }
            }
        }
        if has_required_classes(&value) {
            return Ok(Password(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_have_exact_lengths_and_required_classes() {
        for length in [MIN_LENGTH, 20, 64, MAX_LENGTH] {
            for _ in 0..32 {
                let password = generate(length).unwrap();
                let value = password.as_str();
                assert_eq!(value.len(), length);
                assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                assert!(has_required_classes(value));
                assert!(!format!("{password:?}").contains(value));
            }
        }
    }

    #[test]
    fn invalid_lengths_fail_before_randomness_is_requested() {
        for length in [0, 3, MIN_LENGTH - 1, MAX_LENGTH + 1, usize::MAX] {
            assert!(generate_with(length, |_| panic!("unexpected RNG call")).is_err());
        }
    }

    #[test]
    fn rejection_sampling_skips_biased_bytes() {
        let password = generate_with(12, |bytes| {
            bytes.fill(255);
            for (index, byte) in bytes[..24].iter_mut().enumerate() {
                if index % 2 == 1 {
                    *byte = [0, 26, 52][index / 2 % 3];
                }
            }
            Ok(())
        })
        .unwrap();
        assert!(
            password.as_str() == "Aa0Aa0Aa0Aa0",
            "unexpected public fixture"
        );
    }

    #[test]
    fn incomplete_character_classes_regenerate_the_whole_password() {
        let mut calls = 0;
        let password = generate_with(12, |bytes| {
            calls += 1;
            bytes.fill(0);
            if calls == 2 {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = [1, 27, 53][index % 3];
                }
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert!(
            password.as_str() == "Bb1Bb1Bb1Bb1",
            "unexpected public fixture"
        );
    }

    #[test]
    fn randomness_errors_are_not_replaced_with_a_fallback() {
        let error = generate_with(12, |bytes| {
            bytes.fill(0);
            Err(AppError::new("Secure randomness unavailable."))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "Secure randomness unavailable.");
    }

    #[test]
    fn stored_password_validation_does_not_echo_invalid_data() {
        for value in ["", "SECRET_MARKER", "Aa0123456789\n", "Aa0123456789\u{1b}"] {
            let error = Password::from_stored(Zeroizing::new(value.to_owned())).unwrap_err();
            assert_eq!(error.to_string(), "The stored password has invalid data.");
        }
    }
}
