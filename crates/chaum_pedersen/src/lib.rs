#![feature(async_fn_in_trait)]

extern crate core;
#[macro_use]
extern crate lazy_static;

pub mod chaum_pedersen;
pub mod ecc_chaum_pedersen;
pub mod utils;

pub trait ChaumPedersenTrait {
    type Point;
    type Scalar;

    async fn generate_public_keys(&self, secret_scalar: Self::Scalar)
                                  -> (Self::Point, Self::Point);

    /// This function returns a tuple containing three elements:
    ///
    /// - `t.0`: A randomly generated point `k`.
    ///
    /// - `t.1`: An `Option` wrapping a point. For the ECC implementation, this contains a challenge; otherwise, it contains the value `r1`.
    ///
    /// - `t.2`: An `Option` wrapping a point. For the ECC implementation, this is `None`; otherwise, it contains the value `r2`.
    async fn prover_commit(&self) -> (Self::Scalar, Option<Self::Scalar>, Option<Self::Scalar>);

    fn prover_solve_challenge(
        &self,
        random_k: Self::Scalar,
        challenge: Self::Scalar,
        secret_x: Self::Scalar,
    ) -> Self::Scalar;

    async fn verify_proof(
        &self,
        s: Self::Scalar,
        c: Self::Scalar,
        y1: Self::Point,
        y2: Self::Point,
        r1: Option<Self::Scalar>,
        r2: Option<Self::Scalar>,
    ) -> bool;
}
