# Nodes

This crate provides a distributed proof aggregator, a wallet, and a client for generating and submitting Noir proofs using the Barretenberg backend.

## 🛠️ Environment Setup

First, ensure your system packages are up to date and install the necessary C++ compiler tools required for compiling the Barretenberg FFI bindings.

```bash
# Update the package database
sudo apt update

# Install clang to enable compilation of Barretenberg FFI
sudo apt install clang libc++-dev

```

Next, install Rust to compile the nodes crate:

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

```

## 🔧 Tooling Installation

You will need to install specific versions of the Noir compiler (`nargo`) and the Barretenberg backend (`bb`).

```bash
# Install the installer for Nargo
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash

# Get Nargo version 1.0.0-beta.22
noirup --version 1.0.0-beta.22

# Install the installer for the Barretenberg backend
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash

# Install the Barretenberg backend compatible with this Nargo version
bbup

```

## 📦 Project Setup & Verification

Clone the repository and verify that the underlying Noir circuits compile successfully.

```bash
# Clone this repo containing the circuits and nodes implementations
git clone 'https://github.com/anoma/arm-noir.git'

# Go to where the Noir circuits are defined
cd arm-noir/circuits

# Check that the circuits compile successfully from the CLI
nargo execute

```

### Download Proving System Parameters

The Barretenberg backend requires the Structured Reference String (SRS) parameters and G2 point data.

```bash
# Implicitly download the SRS parameters by generating a verification key
bb prove -b ./target/recursive_no_zk_aggregation.json \
         -w ./target/recursive_no_zk_aggregation.gz \
         -t evm-no-zk \
         -o target \
         --output_format binary \
         -s ultra_honk \
         --write_vk

# Download the G2 point data required by barretenberg-rs
wget "https://crs.aztec-cdn.foundation/g2.dat" -O ~/.bb-crs/bn254_g2.dat

```

## 🚀 Usage

Navigate to the source code for the CLI program:

```bash
cd ../nodes

```

### 🔐 Wallet Management

The `wallet` subcommand allows you to securely generate, store, and manage both transparent (Ethereum-style) and shielded (Sapling-style) keys. All sensitive data is encrypted using age encryption.

**Generate a Transparent Key**

```bash
cargo run --release -- wallet generate --alias my_transparent_key

```

**Generate a Shielded Key**

```bash
cargo run --release -- wallet generate --alias my_shielded_key --shielded

```

**List Wallet Contents**
View all addresses, viewing keys, and payment addresses stored in your local wallet:

```bash
cargo run --release -- wallet list

```

**View Specific Key Details**

```bash
# View public details
cargo run --release -- wallet view --alias my_shielded_key

# Decrypt and view private keys (requires passphrase)
cargo run --release -- wallet view --alias my_shielded_key --decrypt

```

### 💸 Client Operations

The `client` subcommand allows you to interact with the shielded pool, execute transfers (transparent, shielding, shielded, or unshielded), and query balances. *Note: The shielded pool state is tracked locally via a file passed to the `--pool` argument*.

**Check Balances**
Query the balance of a specific wallet alias or address:

```bash
cargo run --release -- client balance \
    --rpc http://127.0.0.1:8545 \
    --pool local_pool.bin \
    --owner my_shielded_key

```

**Execute a Transfer**
Move tokens between addresses or aliases. Depending on the `from` and `to` aliases provided, this seamlessly handles shielding, unshielding, or fully shielded transfers:

```bash
cargo run --release -- client transfer \
    --rpc http://127.0.0.1:8545 \
    --from my_transparent_key \
    --to my_shielded_key \
    --amount 100 \
    --token <ERC20_TOKEN_ADDRESS> \
    --pool local_pool.bin

```

(Optional: Use `--signer <alias>` if the transaction needs to be signed by an Ethereum private key other than the `from` address.)

### ⚙️ Running a Worker Aggregator

You can run the aggregator as a worker node to batch and recursively prove Noir transactions. The following command starts a worker utilizing 64 threads and listening on port `8001`.

```bash
HARDWARE_CONCURRENCY=1 cargo run --release -- aggregator --address 0.0.0.0:8001 --thread-count 64

```

### 🧪 Running Distributed Tests

To run a benchmark test that distributes proof generation work across multiple machines (including TCP streams), run the `bench_mixed_threaded_barretenberg_aggregator` test.

> **Note:** Be sure to manually update the IP addresses of the worker servers inside `src/aggregator.rs` (in the `SUB_AGGREGATORS` constant) before executing this if you are distributing across real remote machines!
> 
> 

```bash
time HARDWARE_CONCURRENCY=1 cargo test --release bench_mixed_threaded_barretenberg_aggregator -- --nocapture

```
