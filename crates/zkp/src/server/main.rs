#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use tonic::transport::Server;

use crate::service::auth_service::AuthService;
use crate::service::zkp::auth_server::AuthServer;

mod service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let addr = "0.0.0.0:50051".parse().expect("invalid address");

    let auth_service = AuthService::new();

    info!("gRPC server started at {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
