use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::model::user_model::UserModel;

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeModel {
    pub challenge: String,
    pub commitment: (String, String),
    pub user: UserModel,
}

impl ChallengeModel {
    pub fn new(challenge: String, commitment: (String, String), user: UserModel) -> Self {
        Self {
            challenge,
            commitment,
            user,
        }
    }

    pub fn generate_auth_id(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish().to_string()
    }
}

impl Display for ChallengeModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Challenge [challenge: {}, user: {}]",
            self.challenge, self.user,
        )
    }
}

impl Hash for ChallengeModel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.challenge.hash(state);
        self.commitment.hash(state);
        self.user.hash(state);
    }
}
