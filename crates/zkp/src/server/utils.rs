use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigInt;
use num_traits::Num;
use sha2::{Digest, Sha256};

pub fn from_str_radix(input: &String) -> BigInt {
    BigInt::from_str_radix(input, 16).expect("Failed to parse string as base-16 BigInt")
}

pub fn generate_session_id(user: &String, solution: &BigInt) -> String {
    // Could happen
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime set before UNIX EPOCH")
        .as_secs();
    let combined = format!("{}||{}||{}", user, iat, solution);
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();
    format!("{:02x}", result)
}
