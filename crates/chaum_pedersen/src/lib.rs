#[macro_use]
extern crate lazy_static;

use num_bigint::{BigInt, ToBigInt};
use std::sync::Arc;
use tokio::try_join;

use crate::utils::generate_random_bigint;

pub mod utils;

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

impl ChaumPedersen {
    pub fn new(p: BigInt, g: BigInt, h: BigInt) -> Self {
        let q = &p - BigInt::from(1);
        Self {
            p: Arc::new(p),
            q,
            g: Arc::new(g),
            h: Arc::new(h),
        }
    }

    pub fn prover_commit(&self, k: &BigInt) -> (BigInt, BigInt) {
        let r1 = self.g.modpow(k, &self.p);
        let r2 = self.h.modpow(k, &self.p);
        (r1, r2)
    }

    pub fn prover_solve_challenge(&self, k: &BigInt, c: &BigInt, x: &BigInt) -> BigInt {
        // The idea behind adding `k + &self.q` is that it will be larger than `c * x` for sure, so `K = q - c * x` will be non-negative.
        let s = (k + &self.q - (c * x)) % &self.q;
        let zero = 0.to_bigint().unwrap();

        // We're still checking for negative result, but this way we may avoid some negative intermediate values.
        if s < zero {
            s + &self.q
        } else {
            s
        }
    }

    pub fn verifier_generate_challenge(&self) -> BigInt {
        generate_random_bigint(&self.q)
    }

    pub async fn verify(
        &self,
        s: BigInt,
        c: BigInt,
        r1: BigInt,
        r2: BigInt,
        y1: BigInt,
        y2: BigInt,
    ) -> bool {
        let g = self.g.clone();
        let h = self.h.clone();
        let p = self.p.clone();

        let s = Arc::new(s);
        let c = Arc::new(c);
        let y1 = Arc::new(y1);
        let y2 = Arc::new(y2);

        let (p_clone, s_clone, c_clone, y1_clone) = (p.clone(), s.clone(), c.clone(), y1.clone());

        let t1 = tokio::spawn(async move {
            (g.modpow(&*s_clone, &p_clone) * y1_clone.modpow(&*c_clone, &p_clone)) % &*p_clone
        });

        let t2 = tokio::spawn(async move { (h.modpow(&*s, &p) * y2.modpow(&*c, &p)) % &*p });

        let (t1, t2) = try_join!(t1, t2).unwrap();

        t1 == r1 && t2 == r2
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;

    #[tokio::test]
    async fn proof_is_valid() {
        let cp = ChaumPedersen::new(P.clone(), G.clone(), H.clone());

        // Register
        // echo -n "nyancat" | openssl dgst -sha256
        let pw = BigInt::from_bytes_be(
            Sign::Plus,
            b"f9f6dc9231fd9c29ef1bc2496093fd3d8a001c82941af955649ec41e31c9aea7",
        );
        let y1 = cp.g.modpow(&pw, &cp.p);
        let y2 = cp.h.modpow(&pw, &cp.p);

        // Prover Commit
        let k = generate_random_bigint(&cp.q);
        let (r1, r2) = cp.prover_commit(&k);

        // Verifier send challenge
        let c = cp.verifier_generate_challenge();

        // Prover solves the challenge
        let s = cp.prover_solve_challenge(&k, &c, &pw);

        // Verify
        let is_valid = cp.verify(s, c, r1, r2, y1, y2).await;

        assert_eq!(is_valid, true)
    }
}
