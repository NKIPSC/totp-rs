use std::{env, process::ExitCode, time::UNIX_EPOCH};

use sha1::Sha1;
use totp_rs::Digits;
use url::{Host, Url};

const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_PERIOD: u64 = 30;

struct Parameters {
    digits: Option<u8>,
    period: Option<u64>,
    secret: Option<Vec<u8>>,
}

impl Parameters {
    fn from_url(url: &Url) -> Parameters {
        let mut digits = None;
        let mut period = None;
        let mut secret = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "digits" => {
                    digits = value.parse().ok();
                }

                "period" => {
                    period = value.parse().ok();
                }

                "secret" => {
                    secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &value);
                }

                _ => continue,
            }
        }

        Parameters {
            digits,
            period,
            secret,
        }
    }
}

/// Minimal example that parses an `otpauth://` URL (via the `url` crate) and
/// generates a TOTP at the current timestamp. The URL must contain the
/// `secret` field. `digits` and `period` are optional and can be omitted, in
/// which case 6 digits and a period of 30 seconds are assumed.
///
/// This example also ignores the `algorithm` parameter which might be
/// specified in the URL, and always assumes Sha1.
fn main() -> ExitCode {
    let Some(url) = env::args().nth(1).and_then(|u| Url::parse(&u).ok()) else {
        eprintln!("usage: cargo run --example authenticator -- [otpauth://]");
        return ExitCode::FAILURE;
    };

    if url.scheme() != "otpauth" || url.host() != Some(Host::Domain("totp")) {
        eprintln!("not a valid otpauth:// URL.");
        return ExitCode::FAILURE;
    }

    let params = Parameters::from_url(&url);

    let Some(secret) = params.secret else {
        eprintln!("secret key is missing");
        return ExitCode::FAILURE;
    };
    let Some(digits) = Digits::arbitrary(params.digits.unwrap_or(DEFAULT_DIGITS)) else {
        eprintln!("number of digits is invalid");
        return ExitCode::FAILURE;
    };
    let period = params.period.unwrap_or(DEFAULT_PERIOD);

    let current_timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let totp = totp_rs::generate::<Sha1>(&secret, current_timestamp, period, digits);
    println!("{totp}");

    ExitCode::SUCCESS
}
