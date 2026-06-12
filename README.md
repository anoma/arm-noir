# ARM OpenVM Noir: Transfer Auth Circuit

This repository contains a Noir-based implementation of the Transfer Authorization logic for the Anoma Resource Machine (ARM). 

This code is almost a translation of the Rust-based OpenVM implementation found in the official Anoma repository: [`arm-openvm/arm_core/src/transfer_auth.rs`](https://github.com/anoma/arm-openvm/blob/master/arm_core/src/transfer_auth.rs).

## Performance Benchmarks

By writing this logic directly as a Noir circuit and proving it with Barretenberg, we bypass the overhead of the zkVM instruction set architecture. 

**Hardware Specifications:**
* CPU: AMD Ryzen™ 9 6900HX (20 MB cache, 8 cores, up to 4.90 GHz)

**Proving Times (CPU):**
* **Noir (This Repo):** **1.968s** *(Note: This excludes 1527 ms for computing the proving key).*
* **OpenVM:** **51.985s**

This represents a ~26.4x speedup in proving time.

## Prerequisites

To compile, execute, and prove this circuit, you will need the Noir toolchain (`nargo`) and the Barretenberg prover CLI (`bb`).

1. Install **Noirup** to get `nargo`:
   ```bash
   curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
   noirup
   ```
2. Install **bbup** to get the Barretenberg CLI (`bb`):
   ```bash
   curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
   bbup
   ```

## Testing

To run the inline tests (including the ephemeral wrap, ephemeral unwrap, persistent consume, and persistent create tests):

```bash
nargo test
```

## Compilation and Execution

Before generating proofs, you must compile the circuit into an intermediate representation (ACIR) and execute it to generate the witness.

1. **Compile the circuit:**
   ```bash
   nargo compile
   ```
   *This generates `./target/arm_openvm_noir.json`.*
2. **Execute the circuit to generate the witness:**
   ```bash
   nargo execute
   ```
   *This generates the witness file at `./target/arm_openvm_noir.gz`.*

## Proving

We use Barretenberg with the Ultraplonk backend to generate EVM-compatible proofs.

**Option 1: Prove and write the Verification Key**
If this is your first time proving, or if the circuit has changed, you will want to write the verification key (`vk`) alongside the proof:

```bash
bb prove -b ./target/arm_openvm_noir.json -w ./target/arm_openvm_noir.gz -t evm --write_vk -o target
```

**Option 2: Standard Prove**
If you already have the verification key generated and just need to generate a new proof for a new witness:

```bash
bb prove -b ./target/arm_openvm_noir.json -w ./target/arm_openvm_noir.gz -t evm -o target
```

Both commands will output a proof file in the `./target/` directory.
