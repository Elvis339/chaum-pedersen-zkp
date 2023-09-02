#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::transport::Server;

use chaum_pedersen::{ChaumPedersen, G, H, P};

use crate::service::auth_service::AuthService;
use crate::service::zkp::auth_server::AuthServer;
use crate::storage::db::KeyValueStorage;

mod service;
mod storage;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let db = Arc::new(Mutex::new(KeyValueStorage::new()));
    let cp = ChaumPedersen::new(P.clone(), G.clone(), H.clone());

    let addr = "0.0.0.0:50051".parse().expect("invalid address");

    let auth_service = AuthService::new(db.clone(), cp);

    info!("gRPC server started at {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
