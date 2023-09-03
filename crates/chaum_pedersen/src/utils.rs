use num_bigint::{BigInt, RandBigInt};

use crate::chaum_pedersen::{ChaumPedersen, G, H, P};
use crate::ecc_chaum_pedersen::EccChaumPedersen;

pub fn generate_random_bigint(bound: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    rng.gen_bigint_range(&BigInt::from(1), &(bound - BigInt::from(1)))
}

pub enum ChaumPedersenFactoryType {
    Interactive(ChaumPedersen),
    NonInteractive(EccChaumPedersen),
}

pub fn chaum_pedersen_factory(is_interactive: bool) -> ChaumPedersenFactoryType {
    if is_interactive {
        ChaumPedersenFactoryType::Interactive(ChaumPedersen::new(P.clone(), G.clone(), H.clone()))
    } else {
        ChaumPedersenFactoryType::NonInteractive(EccChaumPedersen::new())
    }
}
