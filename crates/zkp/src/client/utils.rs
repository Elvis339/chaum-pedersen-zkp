use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};

pub fn sha256(input: &[u8]) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    BigInt::from_bytes_be(Sign::Plus, &result)
}

pub fn to_hex_string(input: BigInt) -> String {
    input.to_str_radix(16)
}
