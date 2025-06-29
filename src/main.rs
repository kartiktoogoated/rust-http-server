use axum::routing::post;
use axum::{Router, routing::get, response::IntoResponse};
use axum::extract::Path;
use axum::extract::Query;
use tokio::signal;
use std::collections::HashMap;
use axum::Json;
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {

    tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer())
    .init();

    let app = Router::new()
        .route("/", get(root))
        .route("/hello", get(hello))
        .route("/goodbye", get(goodbye))
        .route("/greet/{name}", get(greet))
        .route("/search", get(search))
        .route("/login", post(login))
        .layer(TraceLayer::new_for_http());

    println!("Server running on 3000 port");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let shutdown = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        println!("💥 Shutting down gracefully...");
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await.unwrap();

}

async fn root() -> impl IntoResponse {
    "hi root"
}

async fn hello() -> impl IntoResponse {
    "Hello there!"
}

async fn goodbye() -> impl IntoResponse {
    "Goodbye!"
}

async fn greet(Path(name): Path<String>) -> impl IntoResponse {
    format!("Hello, {name}")
}

async fn search(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let query = params.get("q").unwrap_or(&"nothing".to_string()).clone();
    format!("Searching for {query}")
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}
async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    if payload.username == "admin" && payload.password == "admin" {
        "Login success"
    } else {
        "invalid creds"
    }
}