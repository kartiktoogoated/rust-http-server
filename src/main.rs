use axum::{
    extract::{Json, rejection::JsonRejection},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, system_instruction};
use spl_token::instruction::{initialize_mint, mint_to, transfer as spl_transfer};
use spl_associated_token_account::get_associated_token_address;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use bs58;
use base64;

// API wrapper

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// /keypair

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let kp = Keypair::generate(&mut OsRng);
    let pubkey = bs58::encode(kp.public).into_string();
    let secret = bs58::encode(kp.to_bytes()).into_string();
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(KeypairData { pubkey, secret }),
            error: None,
        }),
    )
}

// /token/create

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn create_token(
    body: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<CreateTokenResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.mintAuthority.is_empty() || body.mint.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<CreateTokenResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    let mint_pk = match bs58::decode(&body.mint).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<CreateTokenResponse> {
                    success: false,
                    error: Some("Invalid mint pubkey".into()),
                    data: None,
                }),
            )
        }
    };
    let auth_pk = match bs58::decode(&body.mintAuthority).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<CreateTokenResponse> {
                    success: false,
                    error: Some("Invalid mint authority pubkey".into()),
                    data: None,
                }),
            )
        }
    };
    let program_id = spl_token::id();
    let ix = match initialize_mint(&program_id, &mint_pk, &auth_pk, None, body.decimals) {
        Ok(ix) => ix,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<CreateTokenResponse> {
                    success: false,
                    error: Some(format!("Failed to create instruction: {e}")),
                    data: None,
                }),
            )
        }
    };
    let accounts = ix.accounts.iter().map(|m| AccountMetaResponse {
        pubkey: m.pubkey.to_string(),
        is_signer: m.is_signer,
        is_writable: m.is_writable,
    }).collect();
    let resp = CreateTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

// /token/mint

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn mint_token(
    body: Result<Json<MintTokenRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<MintTokenResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.mint.is_empty() || body.destination.is_empty() || body.authority.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<MintTokenResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    if body.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<MintTokenResponse> {
                success: false,
                error: Some("Invalid amount".into()),
                data: None,
            }),
        );
    }
    let mint_pk = match bs58::decode(&body.mint).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<MintTokenResponse> {
                    success: false,
                    error: Some("Invalid mint pubkey".into()),
                    data: None,
                }),
            )
        }
    };
    let dest_pk = match bs58::decode(&body.destination).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<MintTokenResponse> {
                    success: false,
                    error: Some("Invalid destination pubkey".into()),
                    data: None,
                }),
            )
        }
    };
    let auth_pk = match bs58::decode(&body.authority).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<MintTokenResponse> {
                    success: false,
                    error: Some("Invalid authority pubkey".into()),
                    data: None,
                }),
            )
        }
    };
    let program_id = spl_token::id();
    let ix = match mint_to(&program_id, &mint_pk, &dest_pk, &auth_pk, &[], body.amount) {
        Ok(ix) => ix,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<MintTokenResponse> {
                    success: false,
                    error: Some(format!("Failed to create instruction: {e}")),
                    data: None,
                }),
            )
        }
    };
    let accounts = ix.accounts.iter().map(|m| AccountMetaResponse {
        pubkey: m.pubkey.to_string(),
        is_signer: m.is_signer,
        is_writable: m.is_writable,
    }).collect();
    let resp = MintTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

// /message/sign

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(
    body: Result<Json<SignMessageRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SignMessageResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.message.is_empty() || body.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SignMessageResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    if body.message.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SignMessageResponse> {
                success: false,
                error: Some("Message too long".into()),
                data: None,
            }),
        );
    }
    let sk = match bs58::decode(&body.secret).into_vec() {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SignMessageResponse> {
                    success: false,
                    error: Some("Invalid secret key".into()),
                    data: None,
                }),
            )
        }
    };
    let kp = match Keypair::from_bytes(&sk) {
        Ok(kp) => kp,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SignMessageResponse> {
                    success: false,
                    error: Some("Invalid secret key".into()),
                    data: None,
                }),
            )
        }
    };
    let sig = kp.sign(body.message.as_bytes());
    let resp = SignMessageResponse {
        signature: base64::encode(sig.to_bytes()),
        public_key: bs58::encode(kp.public).into_string(),
        message: body.message,
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

// /message/verify

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(
    body: Result<Json<VerifyMessageRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.message.is_empty() || body.signature.is_empty() || body.pubkey.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<VerifyMessageResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    if body.message.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<VerifyMessageResponse> {
                success: false,
                error: Some("Message too long".into()),
                data: None,
            }),
        );
    }
    let pkb = match bs58::decode(&body.pubkey).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse> {
                    success: false,
                    error: Some("Invalid public key".into()),
                    data: None,
                }),
            )
        }
    };
    let pk = match PublicKey::from_bytes(&pkb) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse> {
                    success: false,
                    error: Some("Invalid public key".into()),
                    data: None,
                }),
            )
        }
    };
    let sigb = match base64::decode(&body.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse> {
                    success: false,
                    error: Some("Invalid signature".into()),
                    data: None,
                }),
            )
        }
    };
    let sig = match Signature::from_bytes(&sigb) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse> {
                    success: false,
                    error: Some("Invalid signature".into()),
                    data: None,
                }),
            )
        }
    };
    let valid = pk.verify(body.message.as_bytes(), &sig).is_ok();
    let resp = VerifyMessageResponse {
        valid,
        message: body.message,
        pubkey: body.pubkey,
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

//  /send/sol

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol(
    body: Result<Json<SendSolRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendSolResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.from.is_empty() || body.to.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SendSolResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    let from_pk = match bs58::decode(&body.from).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendSolResponse> {
                    success: false,
                    error: Some("Invalid from address".into()),
                    data: None,
                }),
            )
        }
    };
    let to_pk = match bs58::decode(&body.to).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendSolResponse> {
                    success: false,
                    error: Some("Invalid to address".into()),
                    data: None,
                }),
            )
        }
    };
    if body.lamports == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SendSolResponse> {
                success: false,
                error: Some("Invalid lamports amount".into()),
                data: None,
            }),
        );
    }
    let ix = system_instruction::transfer(&from_pk, &to_pk, body.lamports);
    let accounts = ix.accounts.iter().map(|m| m.pubkey.to_string()).collect();
    let resp = SendSolResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

// /send/token

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccount>,
    instruction_data: String,
}

async fn send_token(
    body: Result<Json<SendTokenRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(body) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendTokenResponse> {
                    success: false,
                    error: Some("Missing required fields".into()),
                    data: None,
                }),
            )
        }
    };
    if body.destination.is_empty() || body.mint.is_empty() || body.owner.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SendTokenResponse> {
                success: false,
                error: Some("Missing required fields".into()),
                data: None,
            }),
        );
    }
    if body.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SendTokenResponse> {
                success: false,
                error: Some("Invalid amount".into()),
                data: None,
            }),
        );
    }
    let dest_owner = match bs58::decode(&body.destination).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendTokenResponse> {
                    success: false,
                    error: Some("Invalid destination address".into()),
                    data: None,
                }),
            )
        }
    };
    let mint_pk = match bs58::decode(&body.mint).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendTokenResponse> {
                    success: false,
                    error: Some("Invalid mint address".into()),
                    data: None,
                }),
            )
        }
    };
    let owner_pk = match bs58::decode(&body.owner).into_vec() {
        Ok(b) if b.len() == 32 => Pubkey::new(&b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendTokenResponse> {
                    success: false,
                    error: Some("Invalid owner address".into()),
                    data: None,
                }),
            )
        }
    };
    let source_ata = get_associated_token_address(&owner_pk, &mint_pk);
    let dest_ata = get_associated_token_address(&dest_owner, &mint_pk);
    let program_id = spl_token::id();
    let ix = match spl_transfer(&program_id, &source_ata, &dest_ata, &owner_pk, &[], body.amount) {
        Ok(ix) => ix,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<SendTokenResponse> {
                    success: false,
                    error: Some(format!("Failed to create transfer instruction: {e}")),
                    data: None,
                }),
            )
        }
    };
    let accounts = ix.accounts.iter().map(|m| SendTokenAccount {
        pubkey: m.pubkey.to_string(),
        is_signer: m.is_signer,
    }).collect();
    let resp = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(resp),
            error: None,
        }),
    )
}

// Wiring & main

fn app() -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
}

#[tokio::main]
async fn main() {
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app().into_make_service())
        .await
        .unwrap();
}
