use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::{RistrettoPoint, Scalar};
use num_bigint::BigInt;
use num_traits::Num;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

use chaum_pedersen::chaum_pedersen::{ChaumPedersen, G, H, P};
use chaum_pedersen::ChaumPedersenTrait;
use chaum_pedersen::ecc_chaum_pedersen::EccChaumPedersen;
use chaum_pedersen::utils::generate_random_bigint;
use storage::db::{KeyValueStorage, StorageTree};
use storage::model::challenge_model::ChallengeModel;
use storage::model::user_model::UserModel;

use crate::service::zkp::{
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, NonInteractiveAuthenticationRequest, RegisterRequest,
    RegisterResponse,
};
use crate::service::zkp::auth_server::Auth;

pub struct AuthService {
    db: RwLock<KeyValueStorage>,
    cp_protocol: ChaumPedersen,
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let register_request = request.get_ref();
        let user_key = UserModel::user_id(&register_request.user);
        let data = UserModel {
            user: register_request.user.clone(),
            y1: register_request.y1.clone(),
            y2: register_request.y2.clone(),
        };

        self.upsert_user(&user_key, data).await?;
        AuthService::log_success("Registration successful", &register_request.user);
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let challenge_request = request.get_ref();
        let user_key = UserModel::user_id(&challenge_request.user);

        let user = self.get_user(&user_key).await?;
        let (c, auth_id) = self
            .upsert_challenge(challenge_request.clone(), user)
            .await?;

        AuthService::log_success("Challenge issued to the prover auth_id", &auth_id);

        Ok(Response::new(AuthenticationChallengeResponse {
            c,
            auth_id,
        }))
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let authentication_answer_request = request.get_ref();

        let challenge_key = authentication_answer_request.auth_id.encode_to_vec();
        let challenge_model = self.get_challenge_data(&challenge_key).await?;

        // == Params for verification ==
        let solution = AuthService::from_hex_to_bigint(&authentication_answer_request.s);
        let challenge = AuthService::from_hex_to_bigint(&challenge_model.challenge);

        let y1 = AuthService::from_hex_to_bigint(&challenge_model.user.y1);
        let y2 = AuthService::from_hex_to_bigint(&challenge_model.user.y2);

        let r1 = AuthService::from_hex_to_bigint(&challenge_model.commitment.0);
        let r2 = AuthService::from_hex_to_bigint(&challenge_model.commitment.1);

        let is_valid = &self
            .cp_protocol
            .verify_proof(solution, challenge, y1, y2, Some(r1), Some(r2))
            .await;

        let session_id = AuthService::generate_session_id(&challenge_model.user);

        if *is_valid == true {
            return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
        }

        return Err(Status::invalid_argument("Proof is not valid!"));
    }

    async fn non_interactive_authentication(
        &self,
        request: Request<NonInteractiveAuthenticationRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let ecc = EccChaumPedersen::new();
        let ni_request = request.get_ref();

        let (solution, challenge, y1, y2, session_id) =
            self.non_interactive_verification_params(&ni_request).await?;

        if ecc
            .verify_proof(solution, challenge, y1, y2, None, None)
            .await
        {
            return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
        }

        return Err(Status::invalid_argument("Proof is not valid!"));
    }
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            db: RwLock::new(KeyValueStorage::open()),
            cp_protocol: ChaumPedersen::new(P.clone(), G.clone(), H.clone()),
        }
    }

    async fn upsert_user(&self, user_key: &Vec<u8>, data: UserModel) -> Result<(), Status> {
        let mut db = self.db.write().await;
        db.upsert::<UserModel>(StorageTree::Auth, user_key, data)
            .map_err(|e| Status::internal(format!("failed to upsert {}", e)))?;
        Ok(())
    }

    async fn get_user(&self, user_key: &Vec<u8>) -> Result<UserModel, Status> {
        let mut db = self.db.read().await;
        if !db.exists(StorageTree::Auth, &user_key) {
            return Err(Status::not_found("user does not exist"));
        }

        db.get::<UserModel>(StorageTree::Auth, &user_key)
            .map_err(|_| Status::not_found("user not found"))
    }

    async fn get_challenge_data(&self, challenge_key: &Vec<u8>) -> Result<ChallengeModel, Status> {
        let db = self.db.read().await;
        if !db.exists(StorageTree::Challenge, challenge_key) {
            return Err(Status::not_found("challenge does not exist"));
        }

        db.get::<ChallengeModel>(StorageTree::Challenge, challenge_key)
            .map_err(|_| Status::not_found("challenge not found"))
    }

    async fn upsert_challenge(
        &self,
        challenge_request: AuthenticationChallengeRequest,
        user: UserModel,
    ) -> Result<(String, String), Status> {
        let r1: String = challenge_request.r1;
        let r2: String = challenge_request.r2;

        // Generate random challenge
        let challenge = self.cp_protocol.verifier_generate_challenge();
        let challenge_hex = &challenge.to_str_radix(16);

        let challenge_model = ChallengeModel::new(challenge_hex.clone(), (r1, r2), user);

        let auth_id = challenge_model.generate_auth_id();
        let challenge_model_key = auth_id.encode_to_vec();

        let mut db = self.db.write().await;
        db.upsert::<ChallengeModel>(
            StorageTree::Challenge,
            &challenge_model_key,
            challenge_model,
        )
            .map_err(|e| Status::internal(format!("failed to upsert {}", e)))?;

        Ok((challenge_hex.clone(), auth_id))
    }

    async fn non_interactive_verification_params(
        &self,
        ni_request: &NonInteractiveAuthenticationRequest,
    ) -> Result<(Scalar, Scalar, RistrettoPoint, RistrettoPoint, String), Status> {
        let user = self
            .get_user(&UserModel::user_id(&ni_request.user))
            .await?;

        // == Params for verification ==
        let solution: Scalar = serde_json::from_str(&ni_request.s).expect("invalid solution");
        let challenge: Scalar = serde_json::from_str(&ni_request.c).expect("invalid challenge");
        let y1: RistrettoPoint = serde_json::from_str(&user.y1).expect("invalid y1 RistrettoPoint");
        let y2: RistrettoPoint = serde_json::from_str(&user.y2).expect("invalid y1 RistrettoPoint");

        let session_id = AuthService::generate_session_id(&user);

        Ok((solution, challenge, y1, y2, session_id))
    }

    fn log_success<T: std::fmt::Display>(message: &str, value: T) {
        info!("{} {}", message, value);
    }

    fn from_hex_to_bigint(input: &String) -> BigInt {
        BigInt::from_str_radix(input, 16).expect("Failed to parse string as base-16 BigInt")
    }

    fn generate_session_id(user: &UserModel) -> String {
        // Could happen
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime set before UNIX EPOCH")
            .as_secs();

        let combined = format!("{}||{}", user, iat);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        format!("{:02x}", result)
    }
}
