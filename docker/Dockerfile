# Build stage
FROM rust:1.72-buster as build

# Install required packages
RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-dev

# Set working directory
WORKDIR /usr/src

# Copy the entire repo into the Docker image
COPY . .

# Build the server
RUN cargo clean && cargo build --all

# Final stage
FROM debian:buster-slim

ARG APP=/usrc/local/bin
ENV APP_USER=appuser

RUN apt-get update \
    && apt-get install -y ca-certificates

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

# Copy server binary from build stage
COPY --from=build /usr/src/target/debug/zkp_server ${APP}/zkp_server
COPY --from=build /usr/src/target/debug/zkp_client ${APP}/zkp_client

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}
