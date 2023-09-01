use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::Mutex;

use prost::Message;
use tonic::{Request, Response, Status};

use chaum_pedersen::ChaumPedersen;

use crate::service::zkp::auth_server::Auth;
use crate::service::zkp::{
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use crate::storage::db::{KeyValueStorage, StorageTree};
use crate::storage::model::challenge_model::ChallengeModel;
use crate::storage::model::user_model::{user_id, UserModel};
use crate::utils::{from_str_radix, generate_session_id};

pub struct AuthService {
    db: Arc<Mutex<KeyValueStorage>>,
    cp: ChaumPedersen,
}

impl AuthService {
    pub fn new(db: Arc<Mutex<KeyValueStorage>>, cp: ChaumPedersen) -> Self {
        Self { db, cp }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let key = user_id(&request.get_ref().user);

        let data = UserModel::from(request.get_ref().clone());
        let encode = bincode::serialize(&data).expect("failed to serialize auth model");

        let db = &mut self.db.lock().await;
        db.upsert(StorageTree::Auth, &key, encode)
            .expect(&*format!("failed to upsert {:?}", data));

        info!("Registration successful {}", data.user);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let auth_user_key = user_id(&request.get_ref().user);
        let db = &mut self.db.lock().await;

        let exists = db.exists(StorageTree::Auth, &auth_user_key);
        if !exists {
            return Err(Status::not_found(format!(
                "user {} does not exist",
                request.get_ref().user
            )));
        }

        let user_model_raw_data = db
            .get(StorageTree::Auth, &auth_user_key)
            .map_err(|_| Status::not_found("user not found"))?;
        let user: UserModel =
            bincode::deserialize(&user_model_raw_data).expect("failed to deserialize user model");

        let r1: &String = &request.get_ref().r1;
        let r2: &String = &request.get_ref().r2;

        let challenge = &self.cp.verifier_generate_challenge().to_str_radix(16);

        let mut challenged_model =
            ChallengeModel::new(challenge.clone(), (r1.clone(), r2.clone()), user);
        let mut hasher = DefaultHasher::new();
        challenged_model.hash(&mut hasher);
        // We have to convert it to string because of corruption when we have to convert it back to string on line 112
        let auth_id = hasher.finish().to_string();
        let encode =
            bincode::serialize(&challenged_model).expect("failed to serialize challenge model");

        db.upsert(StorageTree::Challenge, &auth_id.encode_to_vec(), encode)
            .expect(format!("failed to upsert challenge {}", challenged_model).as_str());

        info!("Challenge issued to the prover auth_id {}", auth_id);

        Ok(Response::new(AuthenticationChallengeResponse {
            c: challenge.clone(),
            auth_id,
        }))
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let key = request.get_ref().auth_id.encode_to_vec();

        let db = &mut self.db.lock().await;
        let exists = db.exists(StorageTree::Challenge, &key);
        if !exists {
            return Err(Status::not_found(format!(
                "challenge {} does not exist",
                &request.get_ref().auth_id,
            )));
        }

        let raw_data = db.get(StorageTree::Challenge, &key).unwrap();
        let data: ChallengeModel =
            bincode::deserialize(&raw_data).expect("failed to deserialize challenge model");

        let solution = from_str_radix(&request.get_ref().s);
        let challenge = from_str_radix(&data.challenge);
        let y1 = from_str_radix(&data.user.y1);
        let y2 = from_str_radix(&data.user.y2);
        let r1 = from_str_radix(&data.commitment.0);
        let r2 = from_str_radix(&data.commitment.1);

        let is_valid = &self
            .cp
            .verify(solution.clone(), challenge, r1, r2, y1, y2)
            .await;
        info!(
            "Verification for auth_id {} is {}",
            request.get_ref().auth_id,
            is_valid
        );

        let result = generate_session_id(&data.user.user, &solution);

        if *is_valid == true {
            return Ok(Response::new(AuthenticationAnswerResponse {
                session_id: result.to_string(),
            }));
        }

        return Err(Status::invalid_argument("wrong password"));
    }
}
