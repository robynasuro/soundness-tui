use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce, aead::{Aead, KeyInit}};
use base64::{engine::general_purpose, Engine};
use bip39::{Mnemonic, Language};
use ed25519_dalek::{Signer, SigningKey};
use getrandom::getrandom;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use thiserror::Error;

#[wasm_bindgen]
extern "C" {
    // tangkap exception JS kalau pun ada
    #[wasm_bindgen(catch, js_namespace = window, js_name = "sendProofViaJs")]
    async fn send_proof_via_js(
        url: &str,
        body: &str,
        signature: &str,
        public_key: &str
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const ITERATIONS: u32 = 100_000;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Random number generation failed")]
    RngError,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Key derivation failed")]
    KeyDerivationError,
    #[error("Network request failed")]
    NetworkError,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Server rejected request: {0}")]
    ServerRejected(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub public_key_string: String,
    pub encrypted_secret_key: Option<EncryptedSecretKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EncryptedSecretKey {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct KeyStore {
    pub keys: HashMap<String, KeyPair>,
}

#[wasm_bindgen]
pub fn list_keys() -> Result<JsValue, JsValue> {
    let key_store = load_key_store()?;
    let keys_list: Vec<String> = key_store.keys
        .iter()
        .map(|(name, key_pair)| format!("{}: {}", name, key_pair.public_key_string))
        .collect();

    Ok(serde_wasm_bindgen::to_value(&keys_list)?)
}

#[wasm_bindgen]
pub async fn generate_key_pair(name: &str, password: &str) -> Result<JsValue, JsValue> {
    if name.is_empty() || password.is_empty() {
        return Err(JsValue::from_str("Name and password cannot be empty"));
    }

    let mut entropy = [0u8; 32];
    getrandom(&mut entropy).map_err(|_| JsValue::from_str("RNG failed"))?;

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| JsValue::from_str(&format!("Mnemonic error: {:?}", e)))?;

    let signing_key = SigningKey::from_bytes(&entropy);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_string = general_purpose::STANDARD.encode(&public_key_bytes);

    let encrypted_secret = encrypt_secret(&entropy, password)?;

    let mut key_store = load_key_store()?;
    if key_store.keys.contains_key(name) {
        return Err(JsValue::from_str("Key name exists"));
    }

    key_store.keys.insert(
        name.to_string(),
        KeyPair {
            public_key: public_key_bytes.to_vec(),
            public_key_string: public_key_string.clone(),
            encrypted_secret_key: Some(encrypted_secret),
        },
    );

    save_key_store(&key_store)?;

    Ok(serde_wasm_bindgen::to_value(&(public_key_string, mnemonic.to_string()))?)
}

#[wasm_bindgen]
pub async fn import_phrase(phrase: &str, name: &str, password: &str) -> Result<JsValue, JsValue> {
    if phrase.is_empty() || name.is_empty() || password.is_empty() {
        return Err(JsValue::from_str("Phrase, name and password cannot be empty"));
    }

    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {:?}", e)))?;

    let secret_key_bytes = mnemonic.to_entropy();
    if secret_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Invalid entropy length (must be 32 bytes for 24 words)"));
    }

    let secret_key_array: [u8; 32] = secret_key_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Failed to convert secret key"))?;

    let signing_key = SigningKey::from_bytes(&secret_key_array);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_string = general_purpose::STANDARD.encode(&public_key_bytes);

    let encrypted_secret = encrypt_secret(&secret_key_bytes, password)?;

    let mut key_store = load_key_store()?;
    if key_store.keys.contains_key(name) {
        return Err(JsValue::from_str("Key name already exists"));
    }

    key_store.keys.insert(
        name.to_string(),
        KeyPair {
            public_key: public_key_bytes.to_vec(),
            public_key_string: public_key_string.clone(),
            encrypted_secret_key: Some(encrypted_secret),
        },
    );

    save_key_store(&key_store)?;

    Ok(serde_wasm_bindgen::to_value(&(public_key_string, mnemonic.to_string()))?)
}

#[wasm_bindgen]
pub async fn send_proof(
    proof_blob_id: String,
    key_name: String,
    proving_system: String,
    game: Option<String>,
    payload: Option<String>,
    elf_file: Option<String>,
    password: String,
) -> Result<JsValue, JsValue> {
    log(&format!("🔍 [Step 1] Starting proof submission process..."));

    if proof_blob_id.is_empty() || key_name.is_empty() || proving_system.is_empty() {
        return Err(JsValue::from_str("Missing required fields: proof_blob_id, key_name, or proving_system"));
    }

    log(&format!("📁 [Step 1.1] Proof ID: {}", proof_blob_id));
    log(&format!("🔑 [Step 1.2] Key Name: {}", key_name));
    log(&format!("🔧 [Step 1.3] Proving System: {}", proving_system));

    log("📂 [Step 2] Loading key from storage...");
    let key_store = load_key_store()?;
    let key_pair = key_store.keys.get(&key_name)
        .ok_or_else(|| JsValue::from_str(&format!("Key '{}' not found in storage", key_name)))?;

    let encrypted_secret = key_pair.encrypted_secret_key.as_ref()
        .ok_or_else(|| JsValue::from_str("No secret key found for this key pair"))?;

    log("🔐 [Step 3] Decrypting secret key...");
    let secret_key = decrypt_secret(encrypted_secret, &password)
        .map_err(|e| JsValue::from_str(&format!("Failed to decrypt secret key: {}. Please check your password.", e.as_string().unwrap_or_default())))?;

    let secret_key_array: [u8; 32] = secret_key.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key length"))?;

    let signing_key = SigningKey::from_bytes(&secret_key_array);

    log("📦 [Step 4] Processing payload...");
    let payload_value: Value = match payload.as_ref() {
        Some(p) if !p.trim().is_empty() => {
            log(&format!("📦 [Step 4.1] Parsing payload JSON: {} chars", p.len()));
            serde_json::from_str(p)
                .map_err(|e| JsValue::from_str(&format!("Invalid JSON payload: {:?}", e)))?
        },
        _ => {
            log("📦 [Step 4.1] No payload provided, using empty object");
            json!({})
        },
    };

    log("🏗️ [Step 5] Building request body...");
    let proof_filename = "proof.bin";
    let mut request_body = json!({
        "proof_filename": proof_filename,
        "proving_system": proving_system.to_lowercase(),
        "payload": payload_value,
        "proof_blob_id": proof_blob_id,
    });

    let canonical_string = if let Some(game_name) = &game {
        log(&format!("🎮 [Step 5.1] Adding game: {}", game_name));
        request_body["game"] = json!(game_name);
        format!(
            "proof:{}\ngame:{}\nproof_filename:{}\nproving_system:{}",
            request_body["proof_blob_id"].as_str().unwrap_or(""),
            game_name,
            proof_filename,
            proving_system.to_lowercase()
        )
    } else if let Some(elf) = &elf_file {
        log(&format!("📋 [Step 5.1] Adding ELF file: {}", elf));
        request_body["elf_filename"] = json!("program.elf");
        request_body["elf_blob_id"] = json!(elf);
        format!(
            "proof:{}\nelf:{}\nproof_filename:{}\nproving_system:{}",
            request_body["proof_blob_id"].as_str().unwrap_or(""),
            elf,
            proof_filename,
            proving_system.to_lowercase()
        )
    } else {
        return Err(JsValue::from_str("Either game or elf_file must be provided"));
    };

    log("✍️ [Step 6] Signing canonical string...");
    log(&format!("✍️ [Step 6.1] Canonical string: {}", canonical_string));

    let signature_bytes = signing_key.sign(canonical_string.as_bytes());
    let signature = general_purpose::STANDARD.encode(signature_bytes.to_bytes());
    let public_key = key_pair.public_key_string.clone();

    request_body["canonical_string"] = json!(canonical_string);

    let body_str = serde_json::to_string(&request_body)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize request: {:?}", e)))?;

    log("🚀 [Step 7] Sending request to server...");
    log(&format!("🚀 [Step 7.1] Request size: {} bytes", body_str.len()));
    log(&format!("🚀 [Step 7.2] Public key: {}...", &public_key[..20]));
    log(&format!("🚀 [Step 7.3] Signature: {}...", &signature[..20]));

    // panggil JS, tapi tangkap error JS juga
    let response = match send_proof_via_js(
        "/api/soundness-proxy",
        &body_str,
        &signature,
        &public_key
    ).await {
        Ok(v) => v,
        Err(e) => {
            let msg = e.as_string().unwrap_or_else(|| "Proxy threw an exception".to_string());
            return Err(JsValue::from_str(&msg));
        }
    };

    log("📨 [Step 8] Processing server response...");

    let response_obj: Result<Value, _> = serde_wasm_bindgen::from_value(response.clone());

    match response_obj {
        Ok(json_response) => {
            log("✅ [Step 8.1] Successfully parsed response");

            // treat berbagai status error (termasuk SERVER_ERROR dari JS)
            if let Some(status) = json_response.get("status").and_then(|s| s.as_str()) {
                if matches!(status, "ERROR" | "NETWORK_ERROR" | "PROXY_ERROR" | "SERVER_ERROR") {
                    log(&format!("❌ [Step 8.2] Error status: {}", status));

                    let code = json_response.get("server_status").and_then(|v| v.as_i64()).unwrap_or(0);
                    let msg  = json_response.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error");

                    // kembalikan error deskriptif ke UI
                    let mut detailed = format!("{}{}", msg, if code > 0 { format!(" (HTTP {})", code) } else { String::new() });
                    if let Some(details) = json_response.get("server_response") {
                        if details.is_object() || details.is_array() {
                            if let Ok(pretty) = serde_json::to_string_pretty(details) {
                                detailed.push_str("\n\nServer Response:\n");
                                detailed.push_str(&pretty);
                            }
                        }
                    }
                    return Err(JsValue::from_str(&detailed));
                }
            }

            log("🎉 [Step 8.3] Proof submission successful!");
            Ok(response)
        }
        Err(_) => {
            log("❌ [Step 8.2] Failed to parse response as JSON");
            let error_msg = if let Some(error_str) = response.as_string() {
                format!("Server response error: {}", error_str)
            } else {
                "Unknown response format from server".to_string()
            };
            Err(JsValue::from_str(&error_msg))
        }
    }
}

fn encrypt_secret(secret: &[u8], password: &str) -> Result<EncryptedSecretKey, JsValue> {
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom(&mut salt).map_err(|_| JsValue::from_str("Failed to generate salt"))?;
    getrandom(&mut nonce).map_err(|_| JsValue::from_str("Failed to generate nonce"))?;

    let key = derive_key(password, &salt);
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&key));
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), secret)
        .map_err(|_| JsValue::from_str("Encryption failed"))?;

    Ok(EncryptedSecretKey {
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        encrypted_data: encrypted,
    })
}

fn decrypt_secret(encrypted: &EncryptedSecretKey, password: &str) -> Result<Vec<u8>, JsValue> {
    let key = derive_key(password, &encrypted.salt);
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&key));
    cipher.decrypt(Nonce::from_slice(&encrypted.nonce), encrypted.encrypted_data.as_ref())
        .map_err(|_| JsValue::from_str("Wrong password or corrupted data"))
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATIONS, &mut key);
    key
}

fn load_key_store() -> Result<KeyStore, JsValue> {
    let storage = web_sys::window()
        .ok_or_else(|| JsValue::from_str("No window object available"))?
        .local_storage()
        .map_err(|e| JsValue::from_str(&format!("Failed to access localStorage: {:?}", e)))?
        .ok_or_else(|| JsValue::from_str("localStorage not supported"))?;

    let json = storage.get_item("key_store")
        .map_err(|e| JsValue::from_str(&format!("Failed to read from localStorage: {:?}", e)))?
        .unwrap_or_default();

    if json.is_empty() {
        Ok(KeyStore::default())
    } else {
        serde_json::from_str(&json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse key store data: {:?}", e)))
    }
}

fn save_key_store(key_store: &KeyStore) -> Result<(), JsValue> {
    let json = serde_json::to_string(key_store)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize key store: {:?}", e)))?;

    web_sys::window()
        .ok_or_else(|| JsValue::from_str("No window object available"))?
        .local_storage()
        .map_err(|e| JsValue::from_str(&format!("Failed to access localStorage: {:?}", e)))?
        .ok_or_else(|| JsValue::from_str("localStorage not supported"))?
        .set_item("key_store", &json)
        .map_err(|e| JsValue::from_str(&format!("Failed to save to localStorage: {:?}", e)))
}
