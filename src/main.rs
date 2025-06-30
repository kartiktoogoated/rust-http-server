use axum::{Router, routing::post, Json};
use serde::{Serialize, Deserialize};
use solana_sdk::pubkey::Pubkey;
use spl_token::instruction::initialize_mint;
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;
use bs58;
use base64;
use spl_token::instruction::mint_to;


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

async fn mint_token(Json(body): Json<MintTokenRequest>) -> Json<ApiResponse<MintTokenResponse>> {
    // Validate and decode pubkeys
    let mint_pubkey = match bs58::decode(&body.mint).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Pubkey::new(&bytes),
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid mint pubkey".to_string()) }),
    };
    let destination_pubkey = match bs58::decode(&body.destination).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Pubkey::new(&bytes),
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid destination pubkey".to_string()) }),
    };
    let authority_pubkey = match bs58::decode(&body.authority).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Pubkey::new(&bytes),
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid authority pubkey".to_string()) }),
    };

    // SPL token program id
    let token_program = spl_token::id();

    // Build the mint_to instruction
    let ix = match mint_to(
        &token_program,
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        body.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return Json(ApiResponse { success: false, data: None, error: Some(format!("Failed to create instruction: {e}")) }),
    };

    // Format accounts
    let accounts: Vec<AccountMetaResponse> = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    // Instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    let response = MintTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Json(ApiResponse { success: true, data: Some(response), error: None })
}

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

async fn sign_message(Json(body): Json<SignMessageRequest>) -> Json<ApiResponse<SignMessageResponse>> {
    // Validate presence of fields
    if body.message.is_empty() || body.secret.is_empty() {
        return Json(ApiResponse { success: false, data: None, error: Some("Missing required fields".to_string()) });
    }

    // Decode secret from base58
    let secret_bytes = match bs58::decode(&body.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => return Json(ApiResponse { success: false, data: None, error: Some("Invalid secret key".to_string()) }),
    };

    // Parse Keypair from bytes (v1.0 API: to_bytes = secret+public)
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Json(ApiResponse { success: false, data: None, error: Some("Invalid secret key".to_string()) }),
    };

    // Sign the message
    let signature = keypair.sign(body.message.as_bytes());
    let signature_base64 = base64::encode(signature.to_bytes());
    let pubkey_base58 = bs58::encode(keypair.public).into_string();

    let response = SignMessageResponse {
        signature: signature_base64,
        public_key: pubkey_base58,
        message: body.message,
    };

    Json(ApiResponse { success: true, data: Some(response), error: None })
}

fn app() -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
}

#[tokio::main]
async fn main() {
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app().into_make_service())
        .await
        .unwrap();
}
