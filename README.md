# totp-rs
This library provides a dead-simple interface for generating TOTPs, based on [RFC-6238](https://datatracker.ietf.org/doc/html/rfc6238).

## Limitations
This library does not handle the [`otpauth://`](https://en.wikipedia.org/wiki/HMAC-based_one-time_password#otpauth://_URI_scheme) URI scheme, nor does it automatically compute TOTPs based on the current time.
All relevant parameters including key, timestamp, period and number of digits must be provided explicitly when generating a new value.

This library also does _not_ automatically decode base32 keys. 

## Examples
### Generate a TOTP (SHA1)
Requires feature `sha1` (enabled by default).

```rust
use totp_rs::Sha1;

const KEY: &[u8] = b"12345678901234567890";

fn main() {
    //Generate a TOTP with 6 digits, period of 30 seconds at time 0, using the Sha1 algorithm.
    let totp = totp_rs::generate::<Sha1>(KEY, 0, 30, 6);

    //Will print: 755224
    println!("{totp}");
}
```

### Generate a TOTP (SHA256)
Requires feature `sha2` (enabled by default).

```rust
use totp_rs::Sha256;

const KEY: &[u8] = b"12345678901234567890";

fn main() {
    let totp = totp_rs::generate::<Sha256>(KEY, 0, 30, 6);

    //Will print: 875740
    println!("{totp}");
}
```

### Non-RFC-compliant number of digits
Any number of digits between 1 and 9 (inclusive) is allowed, despite the spec only allowing 6, 7 or 8 digits in theory. Values greater than 9 will panic before even attempting to generate the OTP, as the algorithm would panic anyway.

```rust
use totp_rs::Sha1;

const KEY: &[u8] = b"12345678901234567890";

fn main() {
    let totp = totp_rs::generate::<Sha1>(KEY, 0, 30, 9);

    //Will print: 284755224
    println!("{totp}");
}
```

### Fallible conversion
When dealing with an "unknown" (e.g. user-provided) number of digits, `Digits::arbitrary` is provided in order to check whether or not the value is actually valid. `Digits` also implements `TryFrom::<u8>`.

```rust
use totp_rs::{Sha1, Digits};

const KEY: &[u8] = b"12345678901234567890";

fn main() {
    let digits = /* ... */;
    
    if let Some(digits) = Digits::arbitrary(digits) {
        let totp = totp_rs::generate::<Sha1>(KEY, 0, 30, digits);

        //Will print if "digits" is a valid number of digits (1..9)
        println!("{totp}");
    }
}
```