use wasm_bindgen::prelude::*;
use yew::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use crate::core::{generate_key_pair, import_phrase, list_keys, send_proof};
use regex::Regex; // <— NEW

mod core;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // seragam sama core.rs, walau gak dipakai di file ini
    #[wasm_bindgen(catch, js_namespace = window)]
    async fn send_proof_via_js(
        url: &str,
        body: &str,
        signature: &str,
        public_key: &str
    ) -> Result<JsValue, JsValue>;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ParsedCommand {
    pub proof_file: Option<String>,
    pub key_name: Option<String>,
    pub proving_system: Option<String>,
    pub game: Option<String>,
    pub payload: Option<String>,
    pub elf_file: Option<String>,
}

static INIT_LOGGER: std::sync::Once = std::sync::Once::new();
static STARTED: std::sync::Once = std::sync::Once::new();

// NEW: helper untuk bikin URL jadi <a href="...">
fn linkify(text: &str) -> String {
    // regex simple untuk http(s)://... sampai spasi / kutip / tanda < >
    let re = Regex::new(r#"https?://[^\s<>"']+"#).unwrap();
    re.replace_all(text, |caps: &regex::Captures| {
        let url = &caps[0];
        format!(r#"<a href="{0}" target="_blank" rel="noopener noreferrer">{0}</a>"#, url)
    }).into_owned()
}

#[wasm_bindgen]
pub fn parse_cli_command(command: &str) -> Result<JsValue, JsValue> {
    log(&format!("Parsing command: {}", command));
    let args = shlex::split(command).ok_or_else(|| JsValue::from_str("Failed to parse command"))?;
    log(&format!("Parsed args: {:?}", args));

    let mut parsed = ParsedCommand::default();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        log(&format!("Processing argument {}: {}", i, arg));

        let (key, value) = if arg.contains('=') {
            let parts: Vec<&str> = arg.splitn(2, '=').collect();
            (parts[0], parts.get(1).map(|s| s.to_string()))
        } else {
            (arg.as_str(), None)
        };

        match key {
            "soundness-cli" | "send" => {
                i += 1;
                continue;
            }
            "--proof-file" => {
                if let Some(ref val) = value {
                    parsed.proof_file = Some(val.clone());
                    i += 1;
                } else if i + 1 < args.len() {
                    parsed.proof_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --proof-file"));
                }
            }
            "--key-name" => {
                if let Some(ref val) = value {
                    parsed.key_name = Some(val.trim().to_string());
                    i += 1;
                } else if i + 1 < args.len() {
                    parsed.key_name = Some(args[i + 1].trim().to_string());
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --key-name"));
                }
            }
            "--proving-system" => {
                if let Some(ref val) = value {
                    parsed.proving_system = Some(val.clone());
                    i += 1;
                } else if i + 1 < args.len() {
                    parsed.proving_system = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --proving-system"));
                }
            }
            "--game" => {
                if let Some(ref val) = value {
                    parsed.game = Some(val.clone());
                    i += 1;
                } else if i + 1 < args.len() {
                    parsed.game = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --game"));
                }
            }
            "--payload" => {
                if let Some(ref val) = value {
                    if serde_json::from_str::<Value>(val).is_ok() {
                        parsed.payload = Some(val.clone());
                    } else {
                        return Err(JsValue::from_str("Invalid JSON for --payload"));
                    }
                    i += 1;
                } else if i + 1 < args.len() {
                    let val = args[i + 1].clone();
                    if serde_json::from_str::<Value>(&val).is_ok() {
                        parsed.payload = Some(val);
                    } else {
                        return Err(JsValue::from_str("Invalid JSON for --payload"));
                    }
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --payload"));
                }
            }
            "--elf-file" => {
                if let Some(ref val) = value {
                    parsed.elf_file = Some(val.clone());
                    i += 1;
                } else if i + 1 < args.len() {
                    parsed.elf_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(JsValue::from_str("Missing value for --elf-file"));
                }
            }
            _ => {
                log(&format!("Unknown argument: {}", arg));
                return Err(JsValue::from_str(&format!("Unknown argument: {}", arg)));
            }
        }
    }

    log(&format!("Parsed result: {:?}", parsed));
    serde_wasm_bindgen::to_value(&parsed)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_version() -> String {
    "v0.1.0".to_string()
}

#[function_component(App)]
pub fn app() -> Html {
    let command = use_state(|| String::new());
    let parse_result = use_state(|| String::new());
    let generate_key_result = use_state(|| String::new());
    let import_phrase_result = use_state(|| String::new());
    let list_keys_result = use_state(|| String::new());
    let send_proof_result = use_state(|| String::new());
    let key_name = use_state(|| String::new());
    let password = use_state(|| String::new());
    let import_key_name = use_state(|| String::new());
    let import_password = use_state(|| String::new());
    let mnemonic_phrase = use_state(|| String::new());
    let selected_tab = use_state(|| String::from("send"));
    let parsed_command = use_state(|| ParsedCommand::default());
    let is_sending = use_state(|| false);
    let show_password_modal = use_state(|| false);
    let password_error = use_state(|| String::new());
    let mobile_menu_open = use_state(|| false);

    let toggle_mobile_menu = {
        let mobile_menu_open = mobile_menu_open.clone();
        Callback::from(move |_| {
            mobile_menu_open.set(!*mobile_menu_open);
        })
    };

    let on_command_input = {
        let command = command.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            command.set(input.value());
        })
    };

    let on_parse = {
        let command = command.clone();
        let parse_result = parse_result.clone();
        let parsed_command = parsed_command.clone();
        Callback::from(move |_| {
            match parse_cli_command(&command) {
                Ok(result) => {
                    let parsed: ParsedCommand = serde_wasm_bindgen::from_value(result).unwrap_or_default();
                    parsed_command.set(parsed.clone());
                    let mut output = String::new();
                    output.push_str("Parsed command:\n");
                    output.push_str(&format!("Proof File: {}\n", parsed.proof_file.unwrap_or_default()));
                    output.push_str(&format!("Key Name: {}\n", parsed.key_name.unwrap_or_default()));
                    output.push_str(&format!("Proving System: {}\n", parsed.proving_system.unwrap_or_default()));
                    output.push_str(&format!("Game: {}\n", parsed.game.unwrap_or_default()));
                    output.push_str(&format!(
                        "Payload: {}\n",
                        parsed.payload
                            .as_ref()
                            .map(|p| if serde_json::from_str::<Value>(p).is_ok() {
                                "✅ Valid JSON".to_string()
                            } else {
                                "❌ Invalid JSON".to_string()
                            })
                            .unwrap_or_default()
                    ));
                    output.push_str(&format!("ELF File: {}\n", parsed.elf_file.unwrap_or_default()));
                    parse_result.set(output);
                }
                Err(e) => {
                    let error = e.as_string().unwrap_or_else(|| "Unknown error".to_string());
                    parse_result.set(format!("❌ Error: {}", error));
                }
            }
        })
    };

    let on_generate_key = {
        let generate_key_result = generate_key_result.clone();
        let key_name = key_name.clone();
        let password = password.clone();
        Callback::from(move |_| {
            let key_name = key_name.clone();
            let password = password.clone();
            let generate_key_result = generate_key_result.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match generate_key_pair(&key_name, &password).await {
                    Ok(result) => {
                        let (public_key, mnemonic): (String, String) = serde_wasm_bindgen::from_value(result).unwrap_or_default();
                        generate_key_result.set(format!(
                            "✅ Key generated successfully\nPublic Key: {}\nMnemonic: {}",
                            public_key, mnemonic
                        ));
                    }
                    Err(e) => {
                        let error = e.as_string().unwrap_or_else(|| "Unknown error".to_string());
                        generate_key_result.set(format!("❌ Error: {}", error));
                    }
                }
            });
        })
    };

    let on_import_phrase = {
        let import_phrase_result = import_phrase_result.clone();
        let import_key_name = import_key_name.clone();
        let import_password = import_password.clone();
        let mnemonic_phrase = mnemonic_phrase.clone();
        Callback::from(move |_| {
            let import_key_name = import_key_name.clone();
            let import_password = import_password.clone();
            let mnemonic_phrase = mnemonic_phrase.clone();
            let import_phrase_result = import_phrase_result.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match import_phrase(&mnemonic_phrase, &import_key_name, &import_password).await {
                    Ok(result) => {
                        let (public_key, mnemonic): (String, String) = serde_wasm_bindgen::from_value(result).unwrap_or_default();
                        import_phrase_result.set(format!(
                            "✅ Key imported successfully\nPublic Key: {}\nMnemonic: {}",
                            public_key, mnemonic
                        ));
                    }
                    Err(e) => {
                        let error = e.as_string().unwrap_or_else(|| "Unknown error".to_string());
                        import_phrase_result.set(format!("❌ Error: {}", error));
                    }
                }
            });
        })
    };

    let on_list_keys = {
        let list_keys_result = list_keys_result.clone();
        Callback::from(move |_| {
            match list_keys() {
                Ok(result) => {
                    let keys: Vec<String> = serde_wasm_bindgen::from_value(result).unwrap_or_default();
                    if keys.is_empty() {
                        list_keys_result.set("🔑 No keys found".to_string());
                    } else {
                        let output = format!("🔑 Available keys:\n{}", keys.join("\n"));
                        list_keys_result.set(output);
                    }
                }
                Err(e) => {
                    let error = e.as_string().unwrap_or_else(|| "Unknown error".to_string());
                    list_keys_result.set(format!("❌ Error: {}", error));
                }
            }
        })
    };

    let on_open_password_modal = {
        let show_password_modal = show_password_modal.clone();
        let password = password.clone();
        let password_error = password_error.clone();
        Callback::from(move |_| {
            show_password_modal.set(true);
            password.set(String::new());
            password_error.set(String::new());
        })
    };

    let on_password_input = {
        let password = password.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            password.set(input.value());
        })
    };

    let on_send_proof = {
        let send_proof_result = send_proof_result.clone();
        let parsed_command = parsed_command.clone();
        let password = password.clone();
        let is_sending = is_sending.clone();
        let show_password_modal = show_password_modal.clone();
        let password_error = password_error.clone();
        Callback::from(move |_| {
            if password.is_empty() {
                password_error.set("❌ Error: Password is empty".to_string());
                return;
            }
            is_sending.set(true);
            show_password_modal.set(false);
            let send_proof_result = send_proof_result.clone();
            let parsed = parsed_command.clone();
            let password = password.clone();
            let is_sending = is_sending.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match send_proof(
                    parsed.proof_file.as_ref().map_or("", String::as_str).to_string(),
                    parsed.key_name.as_ref().map_or("", String::as_str).to_string(),
                    parsed.proving_system.as_ref().map_or("", String::as_str).to_string(),
                    parsed.game.clone(),
                    parsed.payload.clone(),
                    parsed.elf_file.clone(),
                    password.to_string(),
                ).await {
                    Ok(result) => {
                        let resp: HashMap<String, Value> =
                            serde_wasm_bindgen::from_value(result).unwrap_or_default();

                        let get_str = |k: &str| -> Option<&str> { resp.get(k).and_then(|v| v.as_str()) };

                        let normalize_status = |v: Option<&Value>| -> String {
                            match v {
                                Some(Value::Bool(true))  => "SUCCESS".into(),
                                Some(Value::Bool(false)) => "FAILED".into(),
                                Some(Value::String(s)) => {
                                    let up = s.to_uppercase();
                                    if up == "SUCCESS" || up == "OK" { "SUCCESS".into() }
                                    else if up == "FAILED" || up == "ERROR" { "FAILED".into() }
                                    else { "UNKNOWN".into() }
                                }
                                _ => "UNKNOWN".into()
                            }
                        };

                        let status = get_str("status").unwrap_or("unknown").to_uppercase();
                        let message = get_str("message").unwrap_or("No message");
                        let proving = get_str("proving_system").unwrap_or("UNKNOWN");

                        let proof_verification = normalize_status(
                            resp.get("proof_verification_status").or(resp.get("proof_verification"))
                        );
                        let sui_transaction = normalize_status(
                            resp.get("sui_status").or(resp.get("sui_transaction"))
                        );

                        let transaction_digest = get_str("sui_transaction_digest")
                            .or(get_str("transaction_digest"))
                            .unwrap_or("");

                        let proof_blob_id = get_str("proof_data_blob_id")
                            .or(get_str("proof_blob_id"))
                            .unwrap_or("");

                        let program_blob_id = get_str("program_blob_id")
                            .or(get_str("vk_blob_id"))
                            .unwrap_or("N/A");

                        let suiscan_link = get_str("suiscan_link").unwrap_or("");

                        let (walrus_proof, walrus_vk) =
                            if let Some(arr) = resp.get("walruscan_links").and_then(|v| v.as_array()) {
                                let mut it = arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .filter(|s| !s.is_empty() && *s != "N/A");
                                (it.next().unwrap_or(""), it.next().unwrap_or(""))
                            } else if let Some(obj) = resp.get("walruscan_links").and_then(|v| v.as_object()) {
                                (
                                    obj.get("proof_data").and_then(|v| v.as_str()).unwrap_or(""),
                                    obj.get("vk").and_then(|v| v.as_str()).unwrap_or("")
                                )
                            } else {
                                ("", "")
                            };

                        let mut output = String::new();
                        output.push_str("🎯 Proof Submission Results\n");
                        output.push_str("═══════════════════════════\n");
                        output.push_str(&format!("✅ Status: {}\n", status));
                        output.push_str(&format!("📝 Message: {}\n", message));
                        output.push_str(&format!("🔧 Proving System: {}\n", proving));
                        output.push_str(&format!("🔍 Proof Verification: {}\n", proof_verification));
                        output.push_str(&format!("⛓️ Sui Transaction: {}\n", sui_transaction));
                        output.push_str(&format!("🔗 Transaction Digest: {}\n", transaction_digest));
                        output.push_str(&format!("📦 Proof Blob ID: {}\n", proof_blob_id));
                        output.push_str(&format!("🔑 Program Blob ID: {}\n", program_blob_id));
                        output.push_str(&format!("🔍 Suiscan Link: {}\n", suiscan_link));
                        output.push_str("🌊 Walruscan Links:\n");
                        output.push_str(&format!("   📦 Proof Data: {}\n", walrus_proof));
                        output.push_str(&format!("   🔑 VK: {}\n", walrus_vk));
                        output.push_str("═══════════════════════════");

                        send_proof_result.set(output);
                    }
                    Err(e) => {
                        let error = e.as_string().unwrap_or_else(|| "Unknown error".to_string());
                        send_proof_result.set(format!("❌ Error: {}", error));
                    }
                }
                is_sending.set(false);
                password.set(String::new());
            });
        })
    };

    let on_cancel_password = {
        let show_password_modal = show_password_modal.clone();
        let password = password.clone();
        let password_error = password_error.clone();
        Callback::from(move |_| {
            show_password_modal.set(false);
            password.set(String::new());
            password_error.set(String::new());
        })
    };

    let on_key_name_input = {
        let key_name = key_name.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            key_name.set(input.value());
        })
    };

    let on_import_key_name_input = {
        let import_key_name = import_key_name.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            import_key_name.set(input.value());
        })
    };

    let on_import_password_input = {
        let import_password = import_password.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            import_password.set(input.value());
        })
    };

    let on_import_phrase_input = {
        let mnemonic_phrase = mnemonic_phrase.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            mnemonic_phrase.set(input.value());
        })
    };

    let on_tab_select = {
        let selected_tab = selected_tab.clone();
        let mobile_menu_open = mobile_menu_open.clone();
        Callback::from(move |e: MouseEvent| {
            let target: web_sys::HtmlElement = e.target_unchecked_into();
            if let Some(tab) = target.get_attribute("data-tab") {
                selected_tab.set(tab);
                mobile_menu_open.set(false);
            }
        })
    };

    html! {
        <div class="app-container" id="app-root">
            <header class="app-header">
                <div class="header-content">
                    <h1>{ "Soundness TUI" }</h1>
                    <div class="version">{ "v0.1.0" }</div>
                </div>
                <button class="mobile-menu-btn" onclick={toggle_mobile_menu}>
                    { if *mobile_menu_open { "✕" } else { "☰" } }
                </button>
            </header>

            <nav class={classes!("tab-nav", if *mobile_menu_open { "mobile-open" } else { "" })}>
                <div class="nav-buttons">
                    <button class={classes!("tab-btn", if *selected_tab == "generate" { "active" } else { "" })} data-tab="generate" onclick={on_tab_select.clone()}>{ "Generate Key" }</button>
                    <button class={classes!("tab-btn", if *selected_tab == "import" { "active" } else { "" })} data-tab="import" onclick={on_tab_select.clone()}>{ "Import Phrase" }</button>
                    <button class={classes!("tab-btn", if *selected_tab == "list" { "active" } else { "" })} data-tab="list" onclick={on_tab_select.clone()}>{ "List Keys" }</button>
                    <button class={classes!("tab-btn", if *selected_tab == "send" { "active" } else { "" })} data-tab="send" onclick={on_tab_select.clone()}>{ "Send Proof" }</button>
                </div>
            </nav>

            <main class="main-content">
                {
                    match selected_tab.as_str() {
                        "generate" => html! {
                            <div class="input-group">
                                <h2>{ "Generate Key Pair" }</h2>
                                <div class="form-group">
                                    <label class="form-label">{ "Key Name" }</label>
                                    <input type="text" placeholder="Enter key name" oninput={on_key_name_input.clone()} value={(*key_name).clone()} class="form-input" />
                                </div>
                                <div class="form-group">
                                    <label class="form-label">{ "Password" }</label>
                                    <input type="password" placeholder="Enter password" oninput={on_password_input.clone()} value={(*password).clone()} class="form-input" />
                                </div>
                                <button class="submit-btn" onclick={on_generate_key}>{ "Generate Key" }</button>
                                <div class="output-box"><pre>{ &(*generate_key_result) }</pre></div>
                            </div>
                        },
                        "import" => html! {
                            <div class="input-group">
                                <h2>{ "Import Mnemonic Phrase" }</h2>
                                <div class="form-group">
                                    <label class="form-label">{ "Mnemonic Phrase" }</label>
                                    <input type="text" placeholder="Enter mnemonic phrase" oninput={on_import_phrase_input} value={(*mnemonic_phrase).clone()} class="form-input" />
                                </div>
                                <div class="form-group">
                                    <label class="form-label">{ "Key Name" }</label>
                                    <input type="text" placeholder="Enter key name" oninput={on_import_key_name_input} value={(*import_key_name).clone()} class="form-input" />
                                </div>
                                <div class="form-group">
                                    <label class="form-label">{ "Password" }</label>
                                    <input type="password" placeholder="Enter password" oninput={on_import_password_input} value={(*import_password).clone()} class="form-input" />
                                </div>
                                <button class="submit-btn" onclick={on_import_phrase}>{ "Import Phrase" }</button>
                                <div class="output-box"><pre>{ &(*import_phrase_result) }</pre></div>
                            </div>
                        },
                        "list" => html! {
                            <div class="input-group">
                                <h2>{ "List Keys" }</h2>
                                <button class="submit-btn" onclick={on_list_keys}>{ "Refresh Keys" }</button>
                                <div class="output-box"><pre>{ &(*list_keys_result) }</pre></div>
                            </div>
                        },
                        "send" => html! {
                            <div class="input-group">
                                <h2>{ "Send Proof" }</h2>
                                <div class="form-group">
                                    <label class="form-label">{ "Command" }</label>
                                    <input type="text" placeholder="Enter soundness-cli command" oninput={on_command_input} value={(*command).clone()} class="form-input" />
                                </div>
                                <div class="button-group">
                                    <button class="submit-btn" onclick={on_parse}>{ "Parse Command" }</button>
                                    <button class={if *is_sending { "submit-btn loading" } else { "submit-btn" }} onclick={on_open_password_modal} disabled={(*parsed_command).key_name.is_none() || *is_sending}>
                                        { if *is_sending { "Sending..." } else { "Send Proof" } }
                                    </button>
                                </div>
                                <div class="output-box">
                                {
                                    if *is_sending {
                                        html! { <pre>{ "🔍 [Step 1] Analyzing inputs...\n📁 [Step 1.1] Proof: Detected as Walrus Blob ID\n📁 [Step 1.2] Proof value: <loading>\n📁 [Step 1.3] ELF Program: <loading>\n📂 [Step 2] Processing inputs...\n🔧 [Step 3] Building request body...\n✍️ [Step 4] Signing payload...\n🚀 [Step 5] Sending to server..." }</pre> }
                                    } else {
                                        let combined = (*parse_result).clone() + "\n" + &(*send_proof_result);
                                        let html_str = linkify(&combined);
                                        html! { <pre>{ yew::Html::from_html_unchecked(yew::AttrValue::from(html_str)) }</pre> }
                                    }
                                }
                                </div>
                                {
                                    if *show_password_modal {
                                        html! {
                                            <div class="modal active">
                                                <div class="modal-content">
                                                    <div class="modal-header">{ "Enter Password" }</div>
                                                    <div class="form-group">
                                                        <label class="form-label">{ "Password" }</label>
                                                        <input type="password" placeholder="Enter password to decrypt the secret key" oninput={on_password_input} value={(*password).clone()} class="form-input" />
                                                    </div>
                                                    <div class="output-box"><pre class="error-text">{ &(*password_error) }</pre></div>
                                                    <div class="modal-footer">
                                                        <button class="cancel-btn" onclick={on_cancel_password}>{ "Cancel" }</button>
                                                        <button class="submit-btn" onclick={on_send_proof}>{ "Submit" }</button>
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                    } else { html!{} }
                                }
                            </div>
                        },
                        _ => html! { <div>{ "Invalid tab" }</div> },
                    }
                }
            </main>

            <footer class="app-footer">
                <div class="footer-content">
                    <div class="footer-links">
                        <a href="https://github.com/SoundnessLabs/soundness-layer/tree/main/soundness-cli" target="_blank">{ "Testnet" }</a>
                        <a href="https://github.com/robynasuro/soundness-tui" target="_blank">{ "GitHub" }</a>
                        <a href="https://twitter.com/0xcreamy" target="_blank">{ "Twitter" }</a>
                    </div>
                    <div class="footer-copyright">
                        { "© 2025 Built with ❤️ by 0xcreamy" }
                    </div>
                </div>
            </footer>
        </div>
    }
}

#[wasm_bindgen(start)]
pub fn start_app() -> Result<(), JsValue> {
    STARTED.call_once(|| {
        console_error_panic_hook::set_once();
        INIT_LOGGER.call_once(|| {
            console_log::init_with_level(log::Level::Debug).expect("Failed to init logger");
        });
        log("Starting Soundness TUI application...");
        yew::Renderer::<App>::new().render();
    });
    Ok(())
}
