use num_bigint::{BigInt, RandBigInt};

pub fn generate_random_bigint(bound: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    rng.gen_bigint_range(&BigInt::from(1), &(bound - BigInt::from(1)))
}
