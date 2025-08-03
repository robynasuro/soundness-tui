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
use reqwest::Client;

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

impl From<CryptoError> for JsValue {
    fn from(err: CryptoError) -> Self {
        JsValue::from_str(&err.to_string())
    }
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
    web_sys::console::log_1(&JsValue::from_str(&format!("Listing keys: {:?}", key_store.keys.keys())));
    let keys_list: Vec<String> = key_store.keys
        .iter()
        .map(|(name, key_pair)| format!("{}: {}", name, key_pair.public_key_string))
        .collect();
    
    serde_wasm_bindgen::to_value(&keys_list)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub async fn generate_key_pair(name: &str, password: &str) -> Result<JsValue, JsValue> {
    if name.is_empty() || password.is_empty() {
        return Err(JsValue::from_str("Name and password cannot be empty"));
    }

    let mut entropy = [0u8; 32];
    getrandom(&mut entropy)
        .map_err(|_| JsValue::from_str("Failed to generate entropy"))?;

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate mnemonic: {:?}", e)))?;

    let signing_key = SigningKey::from_bytes(&entropy);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_string = general_purpose::STANDARD.encode(&public_key_bytes);

    let encrypted_secret = encrypt_secret(&entropy, password)?;

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

    serde_wasm_bindgen::to_value(&(public_key_string, mnemonic.to_string()))
        .map_err(|e| JsValue::from_str(&e.to_string()))
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

    serde_wasm_bindgen::to_value(&(public_key_string, mnemonic.to_string()))
        .map_err(|e| JsValue::from_str(&e.to_string()))
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
    if proof_blob_id.is_empty() || key_name.is_empty() || proving_system.is_empty() || password.is_empty() {
        return Err(JsValue::from_str("Proof blob ID, key name, proving system, and password are required"));
    }

    if game.is_none() && elf_file.is_none() {
        return Err(JsValue::from_str("Either game or ELF file must be provided"));
    }

    web_sys::console::log_1(&JsValue::from_str("🔍 [Step 1] Analyzing inputs..."));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "📁 [Step 1.1] Proof: Detected as Walrus Blob ID\n📁 [Step 1.2] Proof value: {}\n📁 [Step 1.3] ELF Program: {}",
        proof_blob_id, if elf_file.is_some() { "Provided" } else { "Not provided (using game mode)" }
    )));

    let key_store = load_key_store()?;
    let key_pair = key_store.keys.get(&key_name)
        .ok_or_else(|| JsValue::from_str(&format!("Key not found: {}", key_name)))?;

    let encrypted_secret = key_pair.encrypted_secret_key.as_ref()
        .ok_or_else(|| JsValue::from_str("No secret key available"))?;
    
    let secret_key = decrypt_secret(encrypted_secret, &password)?;
    let secret_key_array: [u8; 32] = secret_key.as_slice().try_into()
        .map_err(|_| JsValue::from_str("Failed to convert secret key"))?;
    
    let signing_key = SigningKey::from_bytes(&secret_key_array);
    web_sys::console::log_1(&JsValue::from_str("✍️ [Step 4] Signing payload..."));

    let payload_value: Value = match payload {
        Some(p) if !p.trim().is_empty() => serde_json::from_str(&p)
            .map_err(|e| JsValue::from_str(&format!("Invalid payload JSON: {:?}", e)))?,
        _ => json!({}),
    };

    let proof_filename = "proof.bin".to_string();
    let elf_filename = elf_file.as_ref().map(|_| "program.elf".to_string()).unwrap_or_default();

    let mut request_body = json!({
        "proof_filename": proof_filename,
        "proving_system": proving_system.to_lowercase(),
        "payload": payload_value,
    });

    if !proof_blob_id.is_empty() {
        request_body["proof_blob_id"] = json!(proof_blob_id);
    }

    let program_value = if let Some(ref game_name) = game {
        request_body["game"] = json!(game_name);
        game_name.as_str()
    } else if let Some(ref elf) = elf_file {
        request_body["elf_filename"] = json!(elf_filename);
        request_body["elf_blob_id"] = json!(elf);
        elf.as_str()
    } else {
        return Err(JsValue::from_str("Failed to determine program value"));
    };

    web_sys::console::log_1(&JsValue::from_str("📂 [Step 2] Inputs processed successfully"));

    let canonical_string = if elf_file.is_some() {
        format!(
            "proof:{}\nelf:{}\nproof_filename:{}\nelf_filename:{}\nproving_system:{}",
            proof_blob_id,
            program_value,
            proof_filename,
            elf_filename,
            proving_system.to_lowercase()
        )
    } else {
        format!(
            "proof:{}\ngame:{}\nproof_filename:{}\nproving_system:{}",
            proof_blob_id,
            program_value,
            proof_filename,
            proving_system.to_lowercase()
        )
    };
    web_sys::console::log_1(&JsValue::from_str(&format!("🔧 [Step 3.1] Generated canonical string: {}", canonical_string)));

    let signature = general_purpose::STANDARD.encode(signing_key.sign(canonical_string.as_bytes()).to_bytes());
    let public_key = key_pair.public_key_string.clone();
    web_sys::console::log_1(&JsValue::from_str(&format!("✍️ [Step 4.1] Signature generated: {}\n🔑 [Step 4.2] Public key retrieved: {}", signature, public_key)));

    request_body["canonical_string"] = json!(canonical_string);
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "🔧 [Step 3.2] Full request body: {}",
        serde_json::to_string_pretty(&request_body).unwrap_or_default()
    )));

    let client = Client::new();
    web_sys::console::log_1(&JsValue::from_str("🚀 [Step 5] Sending to server..."));
    let response = client
        .post("https://testnet.soundness.xyz/api/proof")
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Public-Key", public_key)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("Network request failed: {:?}", e)))?;
    web_sys::console::log_1(&JsValue::from_str("🚀 [Step 5] Request sent successfully"));

    web_sys::console::log_1(&JsValue::from_str(&format!("📡 [Step 6] Checking response status: {}", response.status())));
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "No error details".to_string());
        return Err(JsValue::from_str(&format!("Server error ({}): {}", status, error_text)));
    }

    let response_json: Value = response.json().await
        .map_err(|e| JsValue::from_str(&format!("Failed to parse response: {:?}", e)))?;

    web_sys::console::log_1(&JsValue::from_str(&format!("📄 Raw server response: {}", response_json.to_string())));

    let result = json!({
        "status": response_json.get("status").and_then(|s| s.as_str()).unwrap_or("UNKNOWN"),
        "message": response_json.get("message").and_then(|m| m.as_str()).unwrap_or("No message"),
        "proving_system": proving_system,
        "proof_verification": response_json.get("proof_verification_status").and_then(|pv| pv.as_bool()).map(|b| if b { "SUCCESS" } else { "FAILED" }).unwrap_or("UNKNOWN"),
        "sui_transaction": response_json.get("sui_status").and_then(|st| st.as_str()).unwrap_or("UNKNOWN"),
        "transaction_digest": response_json.get("sui_transaction_digest").and_then(|td| td.as_str()).unwrap_or(""),
        "proof_blob_id": proof_blob_id,
        "program_blob_id": game.unwrap_or_else(|| elf_file.unwrap_or_default()),
        "suiscan_link": response_json.get("sui_transaction_digest")
            .and_then(|td| td.as_str())
            .map(|digest| format!("https://suiscan.xyz/mainnet/tx/{}", digest))
            .unwrap_or_default(),
        "walruscan_links": {
            "proof_data": response_json.get("proof_data_blob_id")
                .and_then(|id| id.as_str())
                .map(|id| format!("https://walruscan.com/mainnet/blob/{}", id))
                .unwrap_or_default(),
            "vk": response_json.get("vk_blob_id")
                .and_then(|id| id.as_str())
                .map(|id| format!("https://walruscan.com/mainnet/blob/{}", id))
                .unwrap_or_default()
        }
    });

    Ok(serde_wasm_bindgen::to_value(&result)?)
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
        .map_err(|_| JsValue::from_str("Decryption failed: invalid password or corrupted key"))
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATIONS, &mut key);
    key
}

fn load_key_store() -> Result<KeyStore, JsValue> {
    let storage = web_sys::window()
        .ok_or_else(|| JsValue::from_str("No window object"))?
        .local_storage()
        .map_err(|e| JsValue::from_str(&format!("localStorage error: {:?}", e)))?
        .ok_or_else(|| JsValue::from_str("No localStorage"))?;

    let json = storage.get_item("key_store")
        .map_err(|e| JsValue::from_str(&format!("get_item error: {:?}", e)))?
        .unwrap_or_default();
    
    web_sys::console::log_1(&JsValue::from_str(&format!("Loaded key store JSON: {}", json)));
    
    if json.is_empty() {
        web_sys::console::log_1(&JsValue::from_str("Key store is empty, returning default"));
        Ok(KeyStore::default())
    } else {
        serde_json::from_str(&json)
            .map_err(|e| {
                web_sys::console::log_1(&JsValue::from_str(&format!("Failed to parse key store: {:?}", e)));
                JsValue::from_str(&format!("Failed to parse key store: {:?}", e))
            })
    }
}

fn save_key_store(key_store: &KeyStore) -> Result<(), JsValue> {
    let json = serde_json::to_string(key_store)
        .map_err(|e| {
            web_sys::console::log_1(&JsValue::from_str(&format!("Failed to serialize key store: {:?}", e)));
            JsValue::from_str(&format!("Failed to serialize key store: {:?}", e))
        })?;

    web_sys::console::log_1(&JsValue::from_str(&format!("Saving key store: {}", json)));

    web_sys::window()
        .ok_or_else(|| JsValue::from_str("No window object"))?
        .local_storage()
        .map_err(|e| JsValue::from_str(&format!("localStorage error: {:?}", e)))?
        .ok_or_else(|| JsValue::from_str("No localStorage"))?
        .set_item("key_store", &json)
        .map_err(|e| {
            web_sys::console::log_1(&JsValue::from_str(&format!("Failed to save key store: {:?}", e)));
            JsValue::from_str(&format!("Failed to save key store: {:?}", e))
        })
}