use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::service::zkp::RegisterRequest;

/// `UserModel` represents the data model for user authentication.
///
/// This model includes necessary fields from the `RegisterRequest` struct,
/// and may or may not include additional fields specific to the authentication layer.
#[derive(Serialize, Deserialize, Debug)]
pub struct UserModel {
    pub user: String,
    pub y1: String,
    pub y2: String,
}

impl From<RegisterRequest> for UserModel {
    fn from(value: RegisterRequest) -> Self {
        UserModel {
            user: value.user,
            y1: value.y1,
            y2: value.y2,
        }
    }
}

impl Hash for UserModel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.user.hash(state);
        self.y1.hash(state);
        self.y2.hash(state);
    }
}

impl Display for UserModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UserModel [user: {}, y1: {}, y2: {}]",
            self.user, self.y1, self.y2,
        )
    }
}

pub fn user_id(user_name: &String) -> Vec<u8> {
    let mut hasher = DefaultHasher::new();
    let _ = user_name.hash(&mut hasher);
    hasher.finish().encode_to_vec()
}
