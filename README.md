# Chaum Pedersen ZKP
["Cryptography: An Introduction (3rd Edition) Nigel Smart"](https://www.cs.umd.edu/~waa/414-F11/IntroToCrypto.pdf) page 377 section "3. Sigma Protocols" subsection "3.2. Chaum–Pedersen Protocol."  
Public parameters derived from [RF 3526 - 2048](https://www.rfc-editor.org/rfc/rfc3526#page-3)

# How to run

## Without docker
Open two separate terminal windows, in one of the windows run:
- `RUST_LOG=info cargo run --bin zkp_server`
- Register:
  - `RUST_LOG=info cargo run --bin zkp_client register --name Nyan --password cat`
- Login:
  - `RUST_LOG=info cargo run --bin zkp_client login --name Nyan --password cat`

## With docker
- `docker-compose up` will start the server
- `docker exec -it $(docker ps --filter "name=chaum_pedersen_protocol-zkp_server" --format "{{.ID}}") /bin/bash` exec into the container
- Register:
  - `RUST_LOG=info ./zkp_client register --name Nyan --password cat`
- Login:
  - `RUST_LOG=info ./zkp_client login --name Nyan --password cat`
