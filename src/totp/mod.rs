use derive_more::Display;

use rand::{thread_rng, Rng};
use std::error::Error;
use std::time::SystemTimeError;
use totp_rs::{Algorithm, Secret, SecretParseError, TotpUrlError, TOTP};

const ISSUER: &str = "LibreVPN";

pub struct OtpData {
    pub otp_auth_url: String,
    pub otp_base32: String,
}

#[derive(Debug, Display)]
pub struct OtpError(String);

impl Error for OtpError {}

impl From<TotpUrlError> for OtpError {
    fn from(value: TotpUrlError) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

impl std::convert::From<SecretParseError> for OtpError {
    fn from(value: SecretParseError) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

impl std::convert::From<SystemTimeError> for OtpError {
    fn from(value: SystemTimeError) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

pub fn generate_totp(email: &str) -> Result<OtpData, OtpError> {
    // generate random bytes
    let rng = &mut thread_rng();
    let data_byte: [u8; 32] = rng.gen();
    let base32_string = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data_byte);

    let secret = Secret::Encoded(base32_string).to_bytes()?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some(ISSUER.to_string()),
        "".to_string(),
    )?;

    let otp_base32 = totp.get_secret_base32();
    let otp_auth_url =
        format!("otpauth://totp/{ISSUER}:{email}?secret={otp_base32}&issuer={ISSUER}");

    let otp_data = OtpData {
        otp_auth_url,
        otp_base32,
    };

    Ok(otp_data)
}

pub fn totp_is_valid(otp_base32: &String, token: &str) -> Result<bool, OtpError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32.to_string()).to_bytes()?,
        Some("LibreVPN".to_string()),
        "".to_string(),
    )?;

    let is_valid = totp.check_current(token)?;

    Ok(is_valid)
}
