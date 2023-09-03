use std::sync::Arc;

use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign, ToBigInt};
use sha2::{Digest, Sha512};
use tokio::try_join;

use crate::ChaumPedersenTrait;
use crate::utils::generate_random_bigint;

// https://www.rfc-editor.org/rfc/rfc3526#page-3 2048-bt MODP Group
lazy_static! {
        /// Order of the cyclic group G, must be a large prime number.
        /// The elements of the group range from 0 to q - 1. Arithmetic operations are performed module q.
    pub static ref P: BigInt = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16).unwrap();
    pub static ref G: BigInt = 2.to_bigint().unwrap();
    pub static ref H: BigInt = 3.to_bigint().unwrap();
}

#[derive(Debug)]
pub struct ChaumPedersen {
    /// Order of cyclic group G, large prime number
    pub p: Arc<BigInt>,
    /// The largest prime divisor of `p - 1`, `q` specifies the size of the cyclic subgroup
    pub q: BigInt,
    /// Generator of the group which is an element when raised to the power of `q - 1` it generates every element in the group.
    /// {g^0, g^1, g^2, g^3, ..., g^{q-1}}
    pub g: Arc<BigInt>,
    /// Distinct generator from `g` in Chaum-Pedersen protocol `h` is used for proving that the exponent `x` for `g` is the same as for `h`
    /// `y1 = g^x` and `y2 = h^x` then `y1 == y2`
    pub h: Arc<BigInt>,
}

impl ChaumPedersenTrait for ChaumPedersen {
    type Point = BigInt;
    type Scalar = BigInt;

    async fn generate_public_keys(
        &self,
        secret_scalar: Self::Scalar,
    ) -> (Self::Point, Self::Point) {
        let g = self.g.clone();
        let h = self.h.clone();
        let p = self.p.clone();

        // Asynchronously calculate the public keys
        let compute_public_keys = tokio::spawn(async move {
            let y1 = g.modpow(&secret_scalar, &*p);
            let y2 = h.modpow(&secret_scalar, &*p);
            (y1, y2)
        });

        compute_public_keys
            .await
            .expect("failed to compute public keys (y1, y2)")
    }

    async fn prover_commit(&self) -> (Self::Point, Option<Self::Point>, Option<Self::Point>) {
        let modpow_closure = |base: Arc<BigInt>, exp: Arc<BigInt>, modulo: Arc<BigInt>| {
            tokio::spawn(async move { base.modpow(&*exp, &modulo) })
        };

        // Random `k`
        let k = generate_random_bigint(&self.q);

        let r1 = modpow_closure(self.g.clone(), Arc::new(k.clone()), self.p.clone());
        let r2 = modpow_closure(self.h.clone(), Arc::new(k.clone()), self.p.clone());

        let result = try_join!(r1, r2).unwrap();

        (k, Some(result.0), Some(result.1))
    }

    fn prover_solve_challenge(
        &self,
        random_k: Self::Scalar,
        challenge: Self::Scalar,
        secret_x: Self::Scalar,
    ) -> Self::Scalar {
        // The idea behind adding `random_k + &self.q` is that it will be larger than `challenge * secret_x` for sure, so `random_k = q - challenge * secret_x` will be non-negative.
        let s = (random_k + &self.q - (challenge * secret_x)) % &self.q;
        let zero = 0.to_bigint().unwrap();

        // We're still checking for negative result, but this way we may avoid some negative intermediate values.
        if s < zero {
            s + &self.q
        } else {
            s
        }
    }

    async fn verify_proof(
        &self,
        s: Self::Scalar,
        c: Self::Scalar,
        y1: Self::Point,
        y2: Self::Point,
        r1: Option<Self::Scalar>,
        r2: Option<Self::Scalar>,
    ) -> bool {
        let verify_closure = |base1: Arc<BigInt>,
                              exp1: Arc<BigInt>,
                              base2: Arc<BigInt>,
                              exp2: Arc<BigInt>,
                              modulo: Arc<BigInt>| {
            tokio::spawn(async move {
                (base1.modpow(&*exp1, &modulo) * base2.modpow(&*exp2, &modulo)) % &*modulo
            })
        };

        let s = Arc::new(s);
        let c = Arc::new(c);
        let y1 = Arc::new(y1);
        let y2 = Arc::new(y2);

        // We directly use the variables in the first closure and clone them for the second
        let t1 = verify_closure(
            self.g.clone(),
            s.clone(),
            y1.clone(),
            c.clone(),
            self.p.clone(),
        );
        let t2 = verify_closure(
            self.h.clone(),
            s.clone(),
            y2.clone(),
            c.clone(),
            self.p.clone(),
        );

        let (t1, t2) = try_join!(t1, t2).unwrap();

        r1.map(|val| t1 == val).unwrap_or(false) && r2.map(|val| t2 == val).unwrap_or(false)
    }
}

impl ChaumPedersen {
    pub fn new(p: BigInt, g: BigInt, h: BigInt) -> Self {
        let q = &p - BigInt::from(1);
        Self {
            p: Arc::new(p),
            g: Arc::new(g),
            h: Arc::new(h),
            q,
        }
    }

    /// Hash function to convert byte slices to `BigInt` values
    pub fn hash(input: &[u8]) -> BigInt {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result = hasher.finalize();
        BigInt::from_bytes_le(Sign::Plus, result.as_slice())
    }

    pub fn verifier_generate_challenge(&self) -> BigInt {
        generate_random_bigint(&self.q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proof() {
        let cp = ChaumPedersen::new(P.clone(), G.clone(), H.clone());

        // Register
        // echo -n "nyancat" | openssl dgst -sha512
        let secret_x = ChaumPedersen::hash(b"nyancat");
        let (y1, y2) = cp.generate_public_keys(secret_x.clone()).await;

        // Prover Commit
        let (k, r1, r2) = cp.prover_commit().await;

        // Verifier send challenge
        let challenge = cp.verifier_generate_challenge();

        // Prover solves the challenge
        let solution = cp.prover_solve_challenge(k, challenge.clone(), secret_x);

        // Verify
        let is_valid = cp
            .verify_proof(
                solution.clone(),
                challenge.clone(),
                y1,
                y2,
                Some(r1.clone().unwrap()),
                Some(r2.clone().unwrap()),
            )
            .await;
        assert_eq!(is_valid, true);
        let invalid_secret_x = ChaumPedersen::hash(b"nyandog");
        let (invalid_y1, invalid_y2) = cp.generate_public_keys(invalid_secret_x).await;

        assert_eq!(
            cp.verify_proof(
                solution,
                challenge,
                invalid_y1,
                invalid_y2,
                Some(r1.unwrap()),
                Some(r2.unwrap()),
            )
                .await,
            false
        );
    }
}
