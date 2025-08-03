# Soundness TUI

A WebAssembly-based Terminal User Interface (TUI) for submitting proofs to the Soundness testnet. Built with Rust, Yew, and wasm-pack, this application allows users to generate keys, import mnemonic phrases, list keys, and send proofs interactively.

## About

This project is designed to interact with the Soundness testnet API (`https://testnet.soundness.xyz/api/proof`) for proof submission. It’s currently in development, with a focus on simplifying the proof-sending process via a web-based interface.

- **License:** MIT
- **Repo:** [https://github.com/robynasuro/soundness-tui](https://github.com/robynasuro/soundness-tui)
- **Testnet:** [https://testnet.soundness.xyz](https://testnet.soundness.xyz)

## Features

- Generate key pairs with public keys and mnemonics.
- Import mnemonic phrases to create keys.
- List available keys.
- Send proofs with custom commands and payloads.
- Real-time feedback via a web interface.

## Prerequisites

- **Rust** (with `wasm32-unknown-unknown` target)
- **wasm-pack**
- **Node.js** (optional, for proxy testing)
- **Python 3** (for local server)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/robynasuro/soundness-tui.git
cd soundness-tui
```

2. Install Rust and WASM target:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add wasm32-unknown-unknown
```

3. Install wasm-pack:
```bash
cargo install wasm-pack
```

4. Build the project:
```bash
wasm-pack build --target web --release
```

### Development

Build: wasm-pack build --target web --release
Test: Serve with python3 -m http.server 8080 and access via browser.
Contribute: Fork the repo, make changes, and submit a pull request.

Credits

Built by [0xcreamy](https://github.com/robynasuro)
Powered by [Soundness](https://soundness.xyz)
