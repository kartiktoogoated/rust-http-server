use axum::{
    routing::get,
    Router,
    response::IntoResponse,
};

#[tokio::main]
async  fn main() {

    // Router
    let app = Router::new()
        .route("/", get(root))
        .route("/foo", get(get_foo).post(post_foo))
        .route("/foo/bar", get(foo_bar));

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
}

// which calls one of these handlers
async fn root() -> impl IntoResponse {
    "hi root"
}

async fn get_foo() -> impl IntoResponse {
    "hi get foo"
}

async fn post_foo() -> impl IntoResponse {
    "hi post foo"
}

async fn foo_bar() -> impl IntoResponse {
    "hi foo bar"
}

use axum::{
    routing::get,
    response::Json,
    Router,
};
use serde_json::{Value, json};

// `&'static str` becomes a `200 OK` with `content-type: text/plain; charset=utf-8`
async fn plain_text() -> &'static str {
    "foo"
}

// `Json` gives a content-type of `application/json` and works with any type
// that implements `serde::Serialize`
async fn json() -> Json<Value> {
    Json(json!({ "data": 42 }))
}
#[tokio::main]
async fn main() {
    let app = Router::new()
    .route("/plain_text", get(plain_text))
    .route("/json", get(json));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

use axum::{Router, routing::get, response::IntoResponse};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/hello", get(hello))
        .route("/goodbye", get(goodbye));

    println!("Server running on 3000 port");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
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