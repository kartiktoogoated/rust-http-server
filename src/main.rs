use axum::{Router, routing::post, Json};
use serde::{Serialize, Deserialize};
use solana_sdk::pubkey::Pubkey;
use spl_token::instruction::initialize_mint;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use bs58;
use base64;

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

async fn create_token(Json(body): Json<CreateTokenRequest>) -> Json<ApiResponse<CreateTokenResponse>> {
    // Validate and decode pubkeys
    let mint_pubkey = match bs58::decode(&body.mint).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Pubkey::new(&bytes),
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid mint pubkey".to_string()) }),
    };
    let mint_auth_pubkey = match bs58::decode(&body.mintAuthority).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Pubkey::new(&bytes),
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid mint authority pubkey".to_string()) }),
    };

    // The rent sysvar and token program are required by the instruction
    let rent_sysvar = solana_sdk::sysvar::rent::id();
    let token_program = spl_token::id();

    // Build the instruction
    let ix = match initialize_mint(
        &token_program,
        &mint_pubkey,
        &mint_auth_pubkey,
        None, // freeze authority optional
        body.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => return Json(ApiResponse { success: false, data: None, error: Some(format!("Failed to create instruction: {e}")) }),
    };

    // Serialize instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    // Format account metas
    let accounts: Vec<AccountMetaResponse> = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    let response = CreateTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Json(ApiResponse { success: true, data: Some(response), error: None })
}

fn app() -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
}

#[tokio::main]
async fn main() {
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app().into_make_service())
        .await
        .unwrap();
}
