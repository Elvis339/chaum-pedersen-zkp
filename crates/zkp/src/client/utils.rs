use num_bigint::BigInt;

pub fn bigint_to_hex_string(input: BigInt) -> String {
    let bytes = input.to_bytes_be().1;
    hex::encode(bytes)
}
