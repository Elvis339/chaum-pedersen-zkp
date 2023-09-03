#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use clap::{arg, Command};
use num_bigint::BigInt;
use num_traits::Num;
use pretty_env_logger::init;

use chaum_pedersen::chaum_pedersen::ChaumPedersen;
use chaum_pedersen::ChaumPedersenTrait;
use chaum_pedersen::ecc_chaum_pedersen::EccChaumPedersen;
use chaum_pedersen::utils::{chaum_pedersen_factory, ChaumPedersenFactoryType};
use zkp::auth_client::AuthClient;

use crate::utils::bigint_to_hex_string;
use crate::zkp::{
    AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    NonInteractiveAuthenticationRequest, RegisterRequest,
};

mod utils;

pub mod zkp {
    tonic::include_proto!("zkp_auth");
}

fn cli() -> Command {
    Command::new("zkp")
        .about("zkp")
        .subcommand_required(true)
        .subcommand(
            Command::new("register")
                .about("Register or update user")
                .args(&[
                    arg!(--name <NAME> "Username").required(true),
                    arg!(--password <PASSWORD> "Password").required(true),
                    arg!(--algorithm <ALGORITHM> "Choose an algorithm, default algorithm is interactive")
                        .value_parser(["interactive", "non-interactive"]).default_missing_value("default").required(false).num_args(0..=1),
                ]),
        )
        .subcommand(Command::new("login").about("login").args(&[
            arg!(--name <NAME> "Username").required(true),
            arg!(--password <PASSWORD> "Password").required(true),
            arg!(--algorithm <ALGORITHM> "Choose an algorithm, default algorithm is interactive")
                .value_parser(["interactive", "non-interactive"]).default_missing_value("default").required(false).num_args(0..=1),
        ]))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();
    let channel = tonic::transport::Channel::from_static("http://0.0.0.0:50051")
        .connect()
        .await?;

    let mut client = AuthClient::new(channel);
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("register", sub)) => {
            let user_name = sub.get_one::<String>("name").expect("name is required");
            let is_interactive = sub
                .get_one::<String>("algorithm")
                .map(|schema| schema != "non-interactive")
                .unwrap_or(true);

            match chaum_pedersen_factory(is_interactive) {
                ChaumPedersenFactoryType::Interactive(schema) => {
                    info!("Interactive protocol");
                    let secret_x = sub
                        .get_one::<String>("password")
                        .map(|pw| ChaumPedersen::hash(pw.as_bytes()))
                        .expect("password is required");
                    let (y1, y2) = schema.generate_public_keys(secret_x).await;

                    client
                        .register(tonic::Request::new(RegisterRequest {
                            user: user_name.clone(),
                            y1: bigint_to_hex_string(y1),
                            y2: bigint_to_hex_string(y2),
                        }))
                        .await?;
                }
                ChaumPedersenFactoryType::NonInteractive(ecc_schema) => {
                    info!("Non interactive protocol");
                    let secret_x = sub
                        .get_one::<String>("password")
                        .map(|pw| EccChaumPedersen::hash(pw.as_bytes()))
                        .expect("password is required");
                    let (pk_y1, pk_y2) = ecc_schema.generate_public_keys(secret_x).await;

                    client
                        .register(tonic::Request::new(RegisterRequest {
                            user: user_name.clone(),
                            y1: serde_json::to_string(&pk_y1).unwrap(),
                            y2: serde_json::to_string(&pk_y2).unwrap(),
                        }))
                        .await?;
                }
            }
            info!("Successfully registered {}", user_name);
        }
        Some(("login", sub)) => {
            let user_name = sub.get_one::<String>("name").expect("name is required");
            let is_interactive = sub
                .get_one::<String>("algorithm")
                .map(|schema| schema != "non-interactive")
                .unwrap_or(true);

            match chaum_pedersen_factory(is_interactive) {
                ChaumPedersenFactoryType::Interactive(schema) => {
                    info!("Interactive protocol");
                    let secret_x = sub
                        .get_one::<String>("password")
                        .map(|pw| ChaumPedersen::hash(pw.as_bytes()))
                        .expect("password is required");

                    // === Commitment === //
                    let (k, r1, r2) = schema.prover_commit().await;
                    let auth_challenge_response = client
                        .create_authentication_challenge(tonic::Request::new(
                            AuthenticationChallengeRequest {
                                user: user_name.clone(),
                                r1: bigint_to_hex_string(r1.unwrap()), // unwrap because we want to fail if it's None
                                r2: bigint_to_hex_string(r2.unwrap()),
                            },
                        ))
                        .await?;

                    // === Verifier sent the challenge, let's solve it === //
                    let auth_id = &auth_challenge_response.get_ref().auth_id;
                    info!("Commit phase is successful auth_id {}", auth_id);
                    let challenge =
                        BigInt::from_str_radix(&auth_challenge_response.get_ref().c, 16)?;
                    let solution = schema.prover_solve_challenge(k, challenge, secret_x);

                    // Send for verification
                    let verify_response = client
                        .verify_authentication(tonic::Request::new(AuthenticationAnswerRequest {
                            auth_id: auth_id.clone(),
                            s: bigint_to_hex_string(solution),
                        }))
                        .await?;
                    info!(
                        "Received session id {} for {} with auth_id {}",
                        verify_response.get_ref().session_id,
                        user_name,
                        auth_id,
                    );
                }
                ChaumPedersenFactoryType::NonInteractive(ecc_schema) => {
                    info!("Non interactive protocol");
                    let secret_x = sub
                        .get_one::<String>("password")
                        .map(|pw| EccChaumPedersen::hash(pw.as_bytes()))
                        .expect("password is required");

                    // === Commitment === //
                    let (k, challenge, _) = ecc_schema.prover_commit().await;

                    // === Solution === //
                    let solution =
                        ecc_schema.prover_solve_challenge(k, challenge.unwrap(), secret_x);

                    // Send for verification
                    let verify_response = client
                        .non_interactive_authentication(tonic::Request::new(
                            NonInteractiveAuthenticationRequest {
                                user: user_name.to_string(),
                                c: serde_json::to_string(&challenge.unwrap()).unwrap(), // we want to error if something is wrong
                                s: serde_json::to_string(&solution).unwrap(),
                            },
                        ))
                        .await?;
                    info!(
                        "Received session id {} for {}",
                        verify_response.get_ref().session_id,
                        user_name,
                    );
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}
