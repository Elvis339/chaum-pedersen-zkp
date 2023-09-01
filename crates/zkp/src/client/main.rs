#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use clap::{arg, Command};
use num_bigint::BigInt;
use num_traits::Num;
use pretty_env_logger::init;

use chaum_pedersen::{ChaumPedersen, G, H, P};
use chaum_pedersen::utils::generate_random_bigint;
use zkp::auth_client::AuthClient;

use crate::utils::to_hex_string;
use crate::zkp::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};

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
                ]),
        )
        .subcommand(Command::new("login").about("login").args(&[
            arg!(--name <NAME> "Username").required(true),
            arg!(--password <PASSWORD> "Password").required(true),
        ]))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();
    let channel = tonic::transport::Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;

    let mut client = AuthClient::new(channel);
    let matches = cli().get_matches();

    let cp = ChaumPedersen::new(P.clone(), G.clone(), H.clone());

    match matches.subcommand() {
        Some(("register", sub)) => {
            let user_name = sub.get_one::<String>("name").expect("name is required");
            let pw = sub
                .get_one::<String>("password")
                .map(|pw| utils::sha256(pw.as_bytes()))
                .expect("password is required");

            let y1 = cp.g.modpow(&pw, &cp.p);
            // info!("y1 {}", y1);
            let y2 = cp.h.modpow(&pw, &cp.p);
            // info!("y2 {}", y2);

            client
                .register(tonic::Request::new(RegisterRequest {
                    user: user_name.clone(),
                    y1: to_hex_string(y1),
                    y2: to_hex_string(y2),
                }))
                .await?;
        }
        Some(("login", sub)) => {
            let user_name = sub.get_one::<String>("name").expect("name is required");
            let password = sub
                .get_one::<String>("password")
                .map(|pw| utils::sha256(pw.as_bytes()))
                .expect("password is required");

            // Commitment phase
            let k = generate_random_bigint(&cp.q);
            let (r1, r2) = cp.prover_commit(&k);
            // info!("r1 {}", r1);
            // info!("r2 {}", r2);

            let auth_challenge_response = client
                .create_authentication_challenge(tonic::Request::new(
                    AuthenticationChallengeRequest {
                        user: user_name.clone(),
                        r1: to_hex_string(r1),
                        r2: to_hex_string(r2),
                    },
                ))
                .await?;

            // Get the challenge from verifier and solve it
            let auth_id = &auth_challenge_response.get_ref().auth_id;
            info!("Commit phase is successful auth_id {}", auth_id);

            let challenge = BigInt::from_str_radix(&auth_challenge_response.get_ref().c, 16)?;

            let solution = cp.prover_solve_challenge(&k, &challenge, &password);

            // Send for verification
            let verify_response = client
                .verify_authentication(tonic::Request::new(AuthenticationAnswerRequest {
                    auth_id: auth_id.clone(),
                    s: to_hex_string(solution),
                }))
                .await?;
            info!(
                "Received session id {} for {} with auth_id {}",
                verify_response.get_ref().session_id,
                user_name,
                auth_id,
            );
        }
        _ => unreachable!(),
    }

    Ok(())
}
