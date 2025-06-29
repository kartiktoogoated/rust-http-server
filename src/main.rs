use axum::{
    body, extract::{Path, Query}, response::IntoResponse, routing::{get, post}, Json, Router
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

#[tokio::main]
async fn main() {
    // Log layer
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // App routes
    let app = Router::new()
        .route("/", get(root))
        .route("/greet/{name}", get(greet))
        .route("/search", get(search))
        .route("/login", post(login))
        .route("/balance/{address}", get(balance))
        .layer(TraceLayer::new_for_http());

    println!("Server listening on http://localhost:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> impl IntoResponse {
    "Rust HTTP Server is live"
}

async fn greet(Path(name): Path<String>) -> impl IntoResponse {
    format!("Hello, {name}")
}

async fn search(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let q = params.get("q").unwrap_or(&"none".to_string()).clone();
    format!("You searched for: {q}")
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(Json(body): Json<LoginRequest>) -> impl IntoResponse {
    if body.username == "admin" && body.password == "admin" {
        "Login successful" 
    } else {
        "Invalid Credentials"
    }
}

#[derive(Serialize)]
struct BalanceResponse {
    pubkey: String,
    lamports: u64,
}

async fn balance(Path(address): Path<String>) -> impl IntoResponse {
    let client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let pubkey = match address.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => {
            return Json(BalanceResponse {
                pubkey: address,
                lamports: 0,
            });
        }
    };

    let balance = client.get_balance(&pubkey).unwrap_or(0);

    Json(BalanceResponse {
        pubkey: pubkey.to_string(),
        lamports: balance,
    })
}