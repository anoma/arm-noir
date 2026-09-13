pub mod aggregator;
pub mod client;
pub mod wallet;

use nodes::init_srs;
use clap::{Parser, Args, Subcommand};
use aggregator::BarretenbergAggregator;
use std::ops::RangeFrom;
use aggregator::RecursiveAggregator;
use aggregator::VerifierInputs;
use aggregator::ThreadedAggregator;
use aggregator::TcpAggregatorServer;
use aggregator::Aggregator;
use std::net::ToSocketAddrs;
use wallet::Store;
use wallet::ExtendedFullViewingKey;
use wallet::ExtendedSpendingKey;
use wallet::PaymentAddress;
use wallet::Bech32;
use wallet::Bech32Encoded;
use std::path::Path;
use alloy::signers::local::PrivateKeySigner;
use alloy::primitives::Address;
use std::io::Write;
use std::collections::HashMap;
use client::Resource;
use client::DIGEST_BYTES;
use rand::Rng;
use std::path::PathBuf;
use client::TRANSFER_AUTH_CIRCUIT_PATH;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::BarretenbergApi;
use nodes::BarretenbergCircuit;
use alloy::primitives::address;
use wallet::NullifierKey;
use alloy::primitives::keccak256;
use client::TransferAuthWitness;
use client::ValueInfo;
use client::LabelInfo;
use client::ForwarderInfo;
use client::CALL_TYPE_WRAP;
use client::CALL_TYPE_UNWRAP;
use client::PermitInfo;
use noirc_abi::InputMap;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use client::MAX_ETH_ADDR_LEN;
use client::ConsumedResourceWitness;
use client::MerklePath;
use acir::FieldElement;
use acir::AcirField;
use client::MAX_TREE_DEPTH;
use client::MAX_CONSUMED;
use client::MAX_CREATED;
use client::ComplianceWitness;
use client::EmbeddedCurveScalar;
use client::COMPLIANCE_CIRCUIT_PATH;

// ERC-20 forwarder address
const ERC20_FORWARDER_ADDRESS: Address = address!("0x0A62bE41E66841f693f922991C4e40C89cb0CFDF");
const FORWARDER_ADDR_LEN: usize = 20;
const ERC20_TOKEN_ADDR_LEN: usize = 20;
const MAX_AUTH_PK_LEN: usize = 65;
const MAX_ENCRYPTION_PK_LEN: usize = 65;

/// CLI interface for the UltraHonk based AnomaPay implementation
#[derive(Parser)]
#[command(name = "nodes", version, about, long_about = None)]
enum Cli {
    /// Manage the keys that are used in the client and aggregator
    #[command(subcommand)]
    Wallet(WalletCommands),
    /// Run proof aggregator server. Accepts multiple proofs and batches them into one.
    Aggregator(AggregatorArgs),
    /// Submit transfers to the smart contract and do Permit2 approvals
    #[command(subcommand)]
    Client(ClientCommands),
}

#[derive(Args)]
struct AggregatorArgs {
    /// The address at which the aggregator server will run
    #[arg(long)]
    address: String,
    /// Number of aggregator threads to run
    #[arg(long)]
    thread_count: usize,
}


#[derive(Subcommand)]
enum WalletCommands {
    /// Generates a key
    Generate {
        /// Alias to give the generated key
        #[arg(long)]
        alias: String,
        /// Generate a shielded key
        #[arg(long)]
        shielded: bool,
    },
    /// Stores a given bech32 encoded value
    Store {
        /// Alias under which to store the value
        #[arg(long)]
        alias: String,
        /// Spending key, viewing key, payment address, signing key, public key, or Ethereum address
        #[arg(long)]
        value: String,
    },
    /// Lists all keys and addresses in the wallet
    List,
    /// Views non-secret (or secret) details about a given key
    View {
        /// Alias to to display information about
        #[arg(long)]
        alias: String,
        /// Decrypt the data if possible
        #[arg(long)]
        decrypt: bool,
    },
    /// Removes a given alias from the wallet
    Remove {
        /// Alias to remove from the wallet
        #[arg(long)]
        alias: String,
    },
}

#[derive(Subcommand)]
enum ClientCommands {
    /// Effect a transparent, shielding, shielded, or unshielded transfer
    Transfer {
        /// URL of Ethereum RPC to connect to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Spending key or private key to send from
        #[arg(long)]
        from: String,
        /// Ethereum address or transparent address to send to
        #[arg(long)]
        to: String,
        /// The amount to be sent
        #[arg(long)]
        amount: u64,
        /// The token being sent
        #[arg(long)]
        token: String,
        /// The shielded pool to submit transaction to
        #[arg(long)]
        pool: String,
        /// The Ethereum private key that signs the transaction. Defaults to from.
        #[arg(long)]
        signer: Option<String>,
    },
    /// Permit the Permit2 smart contract to spend the signer's tokens
    Approve {
        /// URL of Ethereum RPC to connect to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Address of the Permit2 contract
        #[arg(long)]
        spender: String,
        /// The address authorizing its tokens to be spent
        #[arg(long)]
        signer: String,
        /// The ERC20 token whose spending is being authorized
        #[arg(long)]
        token: String,
    },
}

/// Run a Barretenberg proof aggregator server with several threads
fn aggregator_server<B: ToSocketAddrs>(address: &B, thread_count: usize) {
    type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
    type RecursiveAggregatorT =
        RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
    // Make a more complex aggregator
    let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
    // Push thread_count sub-aggregators to actually handle the computations
    for _i in 0..thread_count {
        recursive_aggregator.insert_sub_aggregator(Box::new(ThreadedAggregator::new(
            0..,
            0..,
            || BarretenbergAggregatorT::new(0usize..),
        )));
    }
    // Build TCP aggregator server using the recursive aggregator
    let mut tcp_aggregator = TcpAggregatorServer::new(&address, recursive_aggregator);
    // Repeatedly accept new connections
    loop {
        if let Err(err) = tcp_aggregator.run() {
            println!("Encountered error in client connection: {:?}", err);
        }
    }
}

// Helper function to prompt for a passphrase
fn prompt_passphrase(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap();
    pass.trim().to_string()
}

// Handle wallet subcommands
fn handle_wallet(cli: WalletCommands) -> Result<(), std::io::Error> {
    let wallet_path = Path::new("wallet.toml");

    // Attempt to load the wallet, or default to empty if it doesn't exist
    let mut store = Store::load(wallet_path).unwrap_or_default();
    let mut rng = rand::thread_rng();

    match cli {
        WalletCommands::Generate { alias, shielded } => {
            let passphrase = prompt_passphrase("Enter passphrase for new key: ");
            if shielded {
                match store.generate_spending_key(alias.clone(), &mut rng, passphrase) {
                    Ok(_) => println!(
                        "Successfully generated shielded spending key for alias: {}",
                        alias
                    ),
                    Err(e) => eprintln!("Error generating shielded key: {:?}", e),
                }
            } else {
                match store.generate_signing_key(alias.clone(), &mut rng, passphrase) {
                    Ok(_) => println!("Successfully generated secret key for alias: {}", alias),
                    Err(e) => eprintln!("Error generating secret key: {:?}", e),
                }
            }
        }
        WalletCommands::Store { alias, value } => {
            // Attempt to parse the value as different known Bech32 types
            if let Ok(fvk) = value.parse::<Bech32Encoded<ExtendedFullViewingKey>>() {
                store.store_viewing_key(alias.clone(), fvk.0);
                println!("Stored FullViewingKey under alias: {}", alias);
            } else if let Ok(pa) = value.parse::<Bech32Encoded<PaymentAddress>>() {
                store.store_payment_address(alias.clone(), pa.0);
                println!("Stored PaymentAddress under alias: {}", alias);
            } else if let Ok(sk) = value.parse::<Bech32Encoded<ExtendedSpendingKey>>() {
                let passphrase = prompt_passphrase("Enter passphrase for new key: ");
                match store.store_spending_key(alias.clone(), &sk.0, passphrase) {
                    Ok(_) => println!("Stored spending key under alias: {}", alias),
                    Err(e) => eprintln!("Error storing spending key: {:?}", e),
                }
            } else if let Ok(addr) = value.parse::<Address>() {
                store.store_address(alias.clone(), addr);
                println!("Stored Address under alias: {}", alias);
            } else if let Ok(signer) = value.parse::<PrivateKeySigner>() {
                let passphrase = prompt_passphrase("Enter passphrase for new key: ");
                match store.store_signing_key(alias.clone(), signer.into_credential(), passphrase) {
                    Ok(_) => println!("Stored secret key under alias: {}", alias),
                    Err(e) => eprintln!("Error storing secret key: {:?}", e),
                }
            } else {
                eprintln!("Failed to parse value as a recognized Bech32 string.");
            }
        }
        WalletCommands::List => {
            println!("--- Wallet Contents ---");
            let mut aliases: Vec<&String> = Vec::new();
            aliases.extend(store.viewing_keys.keys());
            aliases.extend(store.spending_keys.keys());
            aliases.extend(store.payment_addrs.keys());
            aliases.extend(store.signing_keys.keys());
            aliases.extend(store.addresses.keys());

            aliases.sort();
            aliases.dedup();

            if aliases.is_empty() {
                println!("Wallet is empty.");
            } else {
                for alias in aliases {
                    println!("- {}", alias);

                    if let Some(vk) = store.viewing_keys.get(alias) {
                        println!("    Viewing Key: {}", vk);
                    }
                    if let Some(pa) = store.payment_addrs.get(alias) {
                        println!("    Payment Address: {}", pa);
                    }
                    if let Some(addr) = store.addresses.get(alias) {
                        println!("    Address: {:?}", addr);
                    }
                }
            }
        }
        WalletCommands::View { alias, decrypt } => {
            if !store.exists(&alias) {
                println!("Alias '{}' not found in wallet.", alias);
                return Ok(());
            }

            println!("Details for '{}':", alias);

            if let Some(vk) = store.viewing_keys.get(&alias) {
                println!("  Viewing Key: {}", vk);
            }
            if let Some(pa) = store.payment_addrs.get(&alias) {
                println!("  Payment Address: {}", pa);
            }
            if let Some(addr) = store.addresses.get(&alias) {
                println!("  Address: {:?}", addr);
            }

            if decrypt {
                if store.spending_keys.contains_key(&alias) || store.signing_keys.contains_key(&alias) {
                    let passphrase = prompt_passphrase("Enter passphrase to decrypt keys: ");

                    if store.spending_keys.contains_key(&alias) {
                        match store.decrypt_spending_key(alias.clone(), passphrase.clone()) {
                            Ok(sk) => println!("  Decrypted Spending Key: {}", sk.to_bech32m()),
                            Err(e) => eprintln!("  Failed to decrypt spending key: {}", e),
                        }
                    }
                    if store.signing_keys.contains_key(&alias) {
                        match store.decrypt_signing_key(alias.clone(), passphrase) {
                            Ok(sk) => {
                                println!("  Decrypted Secret Key bytes: {}", sk.as_nonzero_scalar())
                            }
                            Err(e) => eprintln!("  Failed to decrypt secret key: {}", e),
                        }
                    }
                } else {
                    println!("  No encrypted keys found for this alias.");
                }
            } else {
                if store.spending_keys.contains_key(&alias) {
                    println!("  [Spending Key is encrypted - use --decrypt to view]");
                }
                if store.signing_keys.contains_key(&alias) {
                    println!("  [Secret Key is encrypted - use --decrypt to view]");
                }
            }
        }
        WalletCommands::Remove { alias } => {
            if store.exists(&alias) {
                store.remove(&alias);
                println!("Removed alias '{}' from wallet.", alias);
            } else {
                println!("Alias '{}' not found.", alias);
            }
        }
    }

    // Always synchronize changes to disk at the end of the operation
    store.synchronize(wallet_path)?;
    Ok(())
}

// Handle client subcommands
fn handle_client(cli: ClientCommands) -> Result<(), std::io::Error> {
    let wallet_path = Path::new("wallet.toml");
    // Attempt to load the wallet, or default to empty if it doesn't exist
    let store = Store::load(wallet_path).unwrap_or_default();
    let mut rng = rand::thread_rng();
    match cli {
        ClientCommands::Transfer { rpc, from, to, token, amount, pool, signer } => {
            // Load up the aggregation circuit from disk
            let logic_program_artifact_path = PathBuf::from(TRANSFER_AUTH_CIRCUIT_PATH);
            // Use the FFI backend which links directly to static libraries
            let backend = FfiBackend::new().unwrap();
            // Initialize the Barretenberg API
            let mut api = BarretenbergApi::new(backend);
            // Load up the aggregation circuit from disk
            let mut logic_circuit = BarretenbergCircuit::new(&mut api, logic_program_artifact_path);
            // The resource logic reference is the UltraHonk verification key hash
            let logic_ref = logic_circuit
                .compute_vk_response
                .hash
                .clone()
                .try_into()
                .expect("verification key hash has incorrect length");
            // Obtain the key to authorize the transaction
            let pksigner = signer.clone().unwrap_or(from.clone());
            let passphrase =
                prompt_passphrase(&format!("Enter passphrase to decrypt {}: ", pksigner));
            let pksigner = store.decrypt_signing_key(pksigner, passphrase)?;
            let pksigner = PrivateKeySigner::from_signing_key(pksigner);
            let mut keys = HashMap::new();
            keys.insert(pksigner.address(), pksigner.clone());
            // Compute the label reference
            let erc20_token_addr = store.evaluate_address(&token)?;
            let mut label_ref_bytes = [0u8; FORWARDER_ADDR_LEN + ERC20_TOKEN_ADDR_LEN];
            label_ref_bytes[..FORWARDER_ADDR_LEN].copy_from_slice(&ERC20_FORWARDER_ADDRESS.as_slice());
            label_ref_bytes[FORWARDER_ADDR_LEN..].copy_from_slice(erc20_token_addr.as_slice());
            let label_ref = keccak256(label_ref_bytes);
            // The label info
            let label_info = LabelInfo {
                forwarder_addr: ERC20_FORWARDER_ADDRESS.into_array(),
                erc20_token_addr: erc20_token_addr.into_array(),
            };
            // The consumed nullifiers
            let mut consumed_nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
            // The consumed data
            let mut consumed_data = [ConsumedResourceWitness::default(); MAX_CONSUMED];
            let mut consumed_count = 0u8;
            // The created data
            let mut created_resources = [Resource::default(); MAX_CREATED];
            let mut created_count = 0u8;
            // Add transaction inputs
            if store.spending_keys.contains_key(&from) {
                // Obtain the key to authorize the transaction
                let passphrase =
                    prompt_passphrase(&format!("Enter passphrase to decrypt {}: ", from));
                let spending_key = store.decrypt_spending_key(from, passphrase)?;
            } else if let Ok(addr) = store.evaluate_address(&from) {
                // Generate randomness for the construction of the resource
                let mut rand_seed = [0u8; DIGEST_BYTES];
                rng.fill(&mut rand_seed);
                let mut nonce = [0u8; DIGEST_BYTES];
                rng.fill(&mut nonce);
                // Generate a nullifier key
                let nullifier_key = NullifierKey::random(&mut rng);
                // Calculate ephemeral value reference
                let mut value_ref = [0u8; 32];
                value_ref[0..MAX_ETH_ADDR_LEN].copy_from_slice(addr.as_slice());
                // The ephemeral resource
                let resource = Resource {
                    value_ref,
                    is_ephemeral: true,
                    rand_seed,
                    nonce,
                    quantity: amount.into(),
                    logic_ref,
                    label_ref: label_ref.0,
                    nk_commitment: nullifier_key.commit().0,
                };
                // The permit info
                let permit_info = PermitInfo {
                    permit_nonce: [0u8; _],
                    permit_deadline: [0u8; _],
                    permit_sig: [0u8; _],
                };
                // The forwarder info
                let forwarder_info = ForwarderInfo {
                    call_type: CALL_TYPE_WRAP,
                    ethereum_account_addr: addr.into_array(),
                    permit: Some(permit_info),
                };
                // The action root
                let action_root = [0u8; DIGEST_BYTES];
                // The transfer authorization witness
                let logic_witness = TransferAuthWitness {
                    resource,
                    is_consumed: true,
                    action_root,
                    nullifier_key: Some(client::NullifierKey { bytes: nullifier_key.0 }),
                    value_info: None,
                    resource_ciphertext: None,
                    resource_ciphertext_len: 0,
                    discovery_ciphertext: None,
                    discovery_ciphertext_len: 0,
                    label_info: Some(label_info),
                    auth_sig: None,
                    forwarder_info: Some(forwarder_info),
                };
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), logic_witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Verification response: {:?}", verify_response);
                // Compliance witness
                let compliance_witness = ConsumedResourceWitness {
                    resource,
                    nf_key: client::NullifierKey { bytes: nullifier_key.0 },
                    cm_merkle_path: MerklePath {
                        path: [(FieldElement::zero(), false); MAX_TREE_DEPTH],
                        depth: MAX_TREE_DEPTH as u32,
                    },
                };
                consumed_data[usize::from(consumed_count)] = compliance_witness;
                let resource_commitment = compliance_witness.resource.commitment();
                let resource_nullifier = compliance_witness.
                    resource
                    .nullifier_from_commitment(compliance_witness.nf_key, resource_commitment);
                consumed_nullifiers[usize::from(consumed_count)] = resource_nullifier;
                consumed_count += 1;
            }
            // Compute the digest of the consumed nullifiers
            let consumed_nullifiers_digest = Resource::hash_nullifiers(consumed_nullifiers, consumed_count.into());
            // Add transaction outputs
            if let Ok(payment_addr) = store.evaluate_payment_address(&to) {
                // Generate randomness for the construction of the resource
                let mut rand_seed = [0u8; DIGEST_BYTES];
                rng.fill(&mut rand_seed);
                // The value info
                let mut value_info = ValueInfo {
                    auth_pk: [0u8; _],
                    encryption_pk: [0u8; _],
                };
                value_info.auth_pk.copy_from_slice(&payment_addr.verifying_key.to_encoded_point(false).as_bytes());
                value_info.encryption_pk.copy_from_slice(&payment_addr.public_key.to_encoded_point(false).as_bytes());
                // Calculate persistent value reference
                let mut value_ref_bytes = [0; MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PK_LEN];
                value_ref_bytes[..MAX_AUTH_PK_LEN].copy_from_slice(&value_info.auth_pk);
                value_ref_bytes[MAX_AUTH_PK_LEN..].copy_from_slice(&value_info.encryption_pk);
                let value_ref = keccak256(value_ref_bytes);
                // Derive the nonce
                let nonce = Resource::derive_nonce(u32::from(created_count), consumed_nullifiers_digest);
                // The permanent resource
                let resource = Resource {
                    value_ref: value_ref.0,
                    is_ephemeral: false,
                    rand_seed,
                    nonce,
                    quantity: amount.into(),
                    logic_ref,
                    label_ref: label_ref.0,
                    nk_commitment: payment_addr.nullifier_key_commitment.0,
                };
                // The action root
                let action_root = [0u8; DIGEST_BYTES];
                // The transfer authorization witness
                let witness = TransferAuthWitness {
                    resource,
                    is_consumed: false,
                    action_root,
                    nullifier_key: None,
                    value_info: Some(value_info),
                    resource_ciphertext: Some([0u8; _]),
                    resource_ciphertext_len: 0,
                    discovery_ciphertext: Some([0u8; _]),
                    discovery_ciphertext_len: 0,
                    label_info: Some(label_info),
                    auth_sig: None,
                    forwarder_info: None,
                };
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Verification response: {:?}", verify_response);
                // Compliance witness
                created_resources[usize::from(created_count)] = resource;
                created_count += 1;
            } else if let Ok(addr) = store.evaluate_address(&to) {
                // Generate randomness for the construction of the resource
                let mut rand_seed = [0u8; DIGEST_BYTES];
                rng.fill(&mut rand_seed);
                // Generate a nullifier key
                let nullifier_key = NullifierKey::random(&mut rng);
                // Calculate ephemeral value reference
                let mut value_ref = [0u8; 32];
                value_ref[0..MAX_ETH_ADDR_LEN].copy_from_slice(addr.as_slice());
                // Derive the nonce
                let nonce = Resource::derive_nonce(u32::from(created_count), consumed_nullifiers_digest);
                // The permanent resource
                let resource = Resource {
                    value_ref,
                    is_ephemeral: true,
                    rand_seed,
                    nonce,
                    quantity: amount.into(),
                    logic_ref,
                    label_ref: label_ref.0,
                    nk_commitment: nullifier_key.commit().0,
                };
                // The forwarder info
                let forwarder_info = ForwarderInfo {
                    call_type: CALL_TYPE_UNWRAP,
                    ethereum_account_addr: addr.into_array(),
                    permit: None,
                };
                // The action root
                let action_root = [0u8; DIGEST_BYTES];
                // The transfer authorization witness
                let witness = TransferAuthWitness {
                    resource,
                    is_consumed: false,
                    action_root,
                    nullifier_key: Some(client::NullifierKey { bytes: nullifier_key.0 }),
                    value_info: None,
                    resource_ciphertext: None,
                    resource_ciphertext_len: 0,
                    discovery_ciphertext: None,
                    discovery_ciphertext_len: 0,
                    label_info: Some(label_info),
                    auth_sig: None,
                    forwarder_info: Some(forwarder_info),
                };
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Verification response: {:?}", verify_response);
                // Compliance witness
                created_resources[usize::from(created_count)] = resource;
                created_count += 1;
            }
            // Construct the compliance witness
            let compliance_witness = ComplianceWitness {
                consumed_data,
                consumed_count: consumed_count.into(),
                created_resources,
                created_count: created_count.into(),
                ephemeral_root: [0u8; _],
                rcv: EmbeddedCurveScalar::random(&mut rng),
            };
            // Load up the aggregation circuit from disk
            let compliance_program_artifact_path = PathBuf::from(COMPLIANCE_CIRCUIT_PATH);
            // Load up the aggregation circuit from disk
            let mut compliance_circuit = BarretenbergCircuit::new(&mut api, compliance_program_artifact_path);
            let mut input_map = InputMap::new();
            input_map.insert("witness".to_string(), compliance_witness.into());
            // Compute the proof from the witness bytes
            let prove_response = compliance_circuit.circuit_prove(&mut api, input_map).unwrap();
            let verify_response = compliance_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
            println!("Verification response: {:?}", verify_response);
        },
        ClientCommands::Approve { rpc, spender, signer, token } => {},
    }
    Ok(())
}

/// Run the aggregator
fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();
    // Initialize the structured reference string
    init_srs();
    // Process CLI arguments
    match cli {
        Cli::Aggregator(args) => {
            // Finally, start the aggregator server
            aggregator_server(&args.address, args.thread_count);
        },
        Cli::Client(cmds) => {
            // Delegate to client functions
            handle_client(cmds)?;
        },
        Cli::Wallet(cmds) => {
            // Delegate to wallet functions
            handle_wallet(cmds)?
        },
    }
    Ok(())
}
