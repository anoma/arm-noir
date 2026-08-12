# Aggregator

This crate provides a distributed aggregator for generating and aggregating Noir proofs using the Barretenberg backend.

## 🛠️ Environment Setup

First, ensure your system packages are up to date and install the necessary C++ compiler tools required for compiling the Barretenberg FFI bindings.

```bash
# Update the package database
sudo apt update

# Install clang to enable compilation of Barretenberg FFI
sudo apt install clang libc++-dev
```

Next, install Rust to compile the aggregator crate:

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
# Clone this repo containing the aggregator
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

Navigate to the source code for the aggregator:

```bash
cd ../aggregator
```

### Running a Worker Aggregator

You can run the aggregator as a worker node. The following command starts a worker utilizing 64 threads and listening on port `8001`.

```bash
HARDWARE_CONCURRENCY=1 cargo run --release -- 0.0.0.0:8001 64
```

### Running Distributed Tests

To run a benchmark test that distributes proof generation work across multiple machines, use the following command. 

> **Note:** Be sure to manually update the IP addresses of the worker servers inside the test file before executing this!

```bash
time HARDWARE_CONCURRENCY=1 cargo test --release bench_mixed_threaded_barretenberg_aggregator -- --nocapture
```
