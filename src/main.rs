use axum::{Router, routing::post, Json};
use serde::Serialize;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use bs58;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> Json<ApiResponse<KeypairData>> {
    let keypair = Keypair::generate(&mut OsRng);
    let pubkey_bs58 = bs58::encode(keypair.public).into_string();
    let secret_bs58 = bs58::encode(keypair.to_bytes()).into_string();

    Json(ApiResponse {
        success: true,
        data: Some(KeypairData {
            pubkey: pubkey_bs58,
            secret: secret_bs58,
        }),
        error: None,
    })
}

fn app() -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair))
}

#[tokio::main]
async fn main() {
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app().into_make_service())
        .await
        .unwrap();
}
