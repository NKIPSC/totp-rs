use hmac::{EagerHash, Hmac, KeyInit, Mac};

#[cfg(feature = "sha1")]
pub type Sha1 = sha1::Sha1;

#[cfg(feature = "sha2")]
pub type Sha256 = sha2::Sha256;
#[cfg(feature = "sha2")]
pub type Sha512 = sha2::Sha512;

/// Checked number of digits to generate a TOTP (1..=9).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digits(u8);

/// Represents an invalid number of digits when a conversion
/// via [`TryFrom`] or [`TryInto`] fails.
///
/// # Examples
/// ```rust
/// use totp_rs::{Digits, InvalidDigits};
///
/// let valid_digits: Result<Digits, InvalidDigits> = 8u8.try_into();
/// assert!(valid_digits.is_ok());
///
/// let invalid_digits: Result<Digits, InvalidDigits> = 0u8.try_into();
/// assert!(invalid_digits.is_err());
/// ```
#[derive(Debug)]
pub struct InvalidDigits {
    _private: u8,
}

/// Generates a new TOTP.
///
/// # Examples
/// ```rust
/// use totp_rs::{generate, Sha1};
///
/// let totp = generate::<Sha1>(b"12345678901234567890", 1787135783, 30, 6);
/// assert_eq!(totp, "352139");
/// ```
///
/// # Panics
/// Panics if the conversion from `digits` into [`Digits`] fails.
pub fn generate<D: EagerHash>(
    key: &[u8],
    time: u64,
    time_step: u64,
    digits: impl TryInto<Digits>,
) -> String {
    let Ok(digits) = digits.try_into() else {
        panic!("digits outside 1..10 range aren't allowed");
    };

    let mut hmac = Hmac::<D>::new_from_slice(key).unwrap();

    let time = time / time_step;
    hmac.update(&time.to_be_bytes());

    let hmac = hmac.finalize().into_bytes();

    let offset = (hmac[hmac.len() - 1] & 0x0F) as usize;
    let binary = (((hmac[offset] & 0x7F) as u32) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | hmac[offset + 3] as u32;

    let otp = binary % 10u32.pow(digits.0 as u32);
    format!("{:0>digits$}", otp, digits = digits.0 as usize)
}

impl Digits {
    /// Generates a TOTP with six digits.
    /// This is equivalent to calling `Digits::arbitrary(6)`, but
    /// it avoids bounds-checking at runtime.
    ///
    /// # Examples
    /// ```rust
    /// use totp_rs::{Digits, Sha1};
    ///
    /// let totp = totp_rs::generate::<Sha1>(b"12345678901234567890", 1787165427, 30, Digits::SIX);
    /// assert_eq!(totp, "936650");
    /// ```
    pub const SIX: Digits = Digits(6);

    /// Generates a TOTP with seven digits.
    /// This is equivalent to calling `Digits::arbitrary(7)`, but
    /// it avoids bounds-checking at runtime.
    ///
    /// # Examples
    /// ```rust
    /// use totp_rs::{Digits, Sha1};
    ///
    /// let totp = totp_rs::generate::<Sha1>(b"12345678901234567890", 1787165427, 30, Digits::SEVEN);
    /// assert_eq!(totp, "1936650");
    /// ```
    pub const SEVEN: Digits = Digits(7);

    /// Generates a TOTP with eight digits.
    /// This is equivalent to calling `Digits::arbitrary(8)`, but
    /// it avoids bounds-checking at runtime.
    ///
    /// # Examples
    /// ```rust
    /// use totp_rs::{Digits, Sha1};
    ///
    /// let totp = totp_rs::generate::<Sha1>(b"12345678901234567890", 1787165427, 30, Digits::EIGHT);
    /// assert_eq!(totp, "51936650");
    /// ```
    pub const EIGHT: Digits = Digits(8);

    /// Constructs [`Digits`] from an arbitrary number of digits ([`u8`]).
    ///
    /// # Examples
    /// ```rust
    /// use totp_rs::Digits;
    ///
    /// let valid_range = Digits::arbitrary(6);
    /// assert_ne!(valid_range, None);
    ///
    /// let invalid_range = Digits::arbitrary(12);
    /// assert_eq!(invalid_range, None);
    /// ```
    pub const fn arbitrary(digits: u8) -> Option<Digits> {
        Some(match digits {
            6 => Digits::SIX,
            7 => Digits::SEVEN,
            8 => Digits::EIGHT,

            //While not explicitly allowed by the spec, the algorithm does
            //work with any value between 1 and 9 digits. Other quantities
            //would panic anyway when trying to generate the TOTP.
            d @ 1..10 => Digits(d),

            _ => return None,
        })
    }
}

impl TryFrom<u8> for Digits {
    type Error = InvalidDigits;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Digits::arbitrary(value).ok_or(InvalidDigits { _private: value })
    }
}

impl From<Digits> for u8 {
    fn from(value: Digits) -> Self {
        value.0
    }
}

//Tests based on samples from https://www.rfc-editor.org/rfc/rfc6238
#[cfg(all(test, feature = "sha1"))]
mod test_sha1 {
    use crate::{Sha1, generate};

    const KEY_SHA1: &[u8] = b"12345678901234567890";
    const TIME_STEP: u64 = 30;

    #[test]
    fn sha1() {
        assert_eq!(generate::<Sha1>(KEY_SHA1, 59, TIME_STEP, 8), "94287082");
        assert_eq!(
            generate::<Sha1>(KEY_SHA1, 1111111109, TIME_STEP, 8),
            "07081804"
        );
        assert_eq!(
            generate::<Sha1>(KEY_SHA1, 1111111111, TIME_STEP, 8),
            "14050471"
        );
        assert_eq!(
            generate::<Sha1>(KEY_SHA1, 1234567890, TIME_STEP, 8),
            "89005924"
        );
        assert_eq!(
            generate::<Sha1>(KEY_SHA1, 2000000000, TIME_STEP, 8),
            "69279037"
        );
        assert_eq!(
            generate::<Sha1>(KEY_SHA1, 20000000000, TIME_STEP, 8),
            "65353130"
        );
    }
}

//Tests based on samples from https://www.rfc-editor.org/rfc/rfc6238
#[cfg(all(test, feature = "sha2"))]
mod test_sha2 {
    use crate::{Sha256, Sha512, generate};

    const KEY_SHA256: &[u8] = b"12345678901234567890123456789012";
    const KEY_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    const TIME_STEP: u64 = 30;

    #[test]
    fn sha256() {
        assert_eq!(generate::<Sha256>(KEY_SHA256, 59, TIME_STEP, 8), "46119246");
        assert_eq!(
            generate::<Sha256>(KEY_SHA256, 1111111109, TIME_STEP, 8),
            "68084774"
        );
        assert_eq!(
            generate::<Sha256>(KEY_SHA256, 1111111111, TIME_STEP, 8),
            "67062674"
        );
        assert_eq!(
            generate::<Sha256>(KEY_SHA256, 1234567890, TIME_STEP, 8),
            "91819424"
        );
        assert_eq!(
            generate::<Sha256>(KEY_SHA256, 2000000000, TIME_STEP, 8),
            "90698825"
        );
        assert_eq!(
            generate::<Sha256>(KEY_SHA256, 20000000000, TIME_STEP, 8),
            "77737706"
        );
    }

    #[test]
    fn sha512() {
        assert_eq!(generate::<Sha512>(KEY_SHA512, 59, TIME_STEP, 8), "90693936");
        assert_eq!(
            generate::<Sha512>(KEY_SHA512, 1111111109, TIME_STEP, 8),
            "25091201"
        );
        assert_eq!(
            generate::<Sha512>(KEY_SHA512, 1111111111, TIME_STEP, 8),
            "99943326"
        );
        assert_eq!(
            generate::<Sha512>(KEY_SHA512, 1234567890, TIME_STEP, 8),
            "93441116"
        );
        assert_eq!(
            generate::<Sha512>(KEY_SHA512, 2000000000, TIME_STEP, 8),
            "38618901"
        );
        assert_eq!(
            generate::<Sha512>(KEY_SHA512, 20000000000, TIME_STEP, 8),
            "47863826"
        );
    }
}
