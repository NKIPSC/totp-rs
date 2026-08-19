use hmac::{EagerHash, Hmac, KeyInit, Mac};

#[cfg(feature = "sha1")]
pub type Sha1 = sha1::Sha1;

#[cfg(feature = "sha2")]
pub type Sha256 = sha2::Sha256;
#[cfg(feature = "sha2")]
pub type Sha512 = sha2::Sha512;

pub fn generate<D: EagerHash>(key: &[u8], time: u64, time_step: u64, digits: u8) -> String {
    if !(1..=8).contains(&digits) {
        panic!("Number of digits must be between 1 and 8");
    }

    let mut hmac = Hmac::<D>::new_from_slice(key).unwrap();

    let time = time / time_step;
    hmac.update(&time.to_be_bytes());

    let hmac = hmac.finalize().into_bytes();

    let offset = (hmac[hmac.len() - 1] & 0x0F) as usize;
    let binary = (((hmac[offset] & 0x7F) as u32) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | hmac[offset + 3] as u32;

    let otp = binary % 10u32.pow(digits as u32);
    format!("{:0>digits$}", otp, digits = digits as usize)
}

//Tests based on samples from https://www.rfc-editor.org/rfc/rfc6238
#[cfg(test)]
mod test {
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    use crate::generate;

    const KEY_SHA1: &[u8] = b"12345678901234567890";
    const KEY_SHA256: &[u8] = b"12345678901234567890123456789012";
    const KEY_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

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
