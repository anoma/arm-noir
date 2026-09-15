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
use std::collections::BTreeSet;
use client::Nullifier;
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::BTreeMap;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;
use client::ResourceLogicInstance;
use client::AppData;
use client::ExpirableBlob;
use client::encode_wrap_forwarder_input;
use client::encode_forwarder_calldata;
use client::encode_unwrap_forwarder_input;

// ERC-20 forwarder address
const ERC20_FORWARDER_ADDRESS: Address = address!("0x0A62bE41E66841f693f922991C4e40C89cb0CFDF");
const FORWARDER_ADDR_LEN: usize = 20;
const ERC20_TOKEN_ADDR_LEN: usize = 20;
const MAX_AUTH_PK_LEN: usize = 65;
const MAX_ENCRYPTION_PK_LEN: usize = 65;
const MAX_OUTPUT_LEN: usize = 64;

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

// State of the shielded pool
#[derive(Default, BorshSerialize, BorshDeserialize, Clone)]
struct PoolState {
    // Nodes not yet in the tree
    note_queue: Vec<Resource>,
    // Nullifiers not yet processed
    nullifier_queue: Vec<Nullifier>,
}

// The client's view of the shielded pool
#[derive(Default, BorshSerialize, BorshDeserialize, Debug)]
struct ClientState {
    // Map viewing keys to the notes they own
    pos_map: HashMap<ExtendedFullViewingKey, BTreeSet<u64>>,
    // Map nullifiers to note positions they nullify
    nf_map: HashMap<Nullifier, u64>,
    // Map note position to notes
    note_map: BTreeMap<u64, Resource>,
    // Set of spent note positions
    spent_notes: BTreeSet<u64>,
    // The pool's current position
    current_pos: u64,
}

impl ClientState {
    fn synchronize(pool: PoolState, fvks: &[ExtendedFullViewingKey]) -> Self {
        let mut state = Self::default();
        // Scan the notes in the queue
        for resource in pool.note_queue {
            state.note_map.insert(state.current_pos, resource);
            for fvk in fvks {
                if resource.nk_commitment == fvk.nullifier_key.commit().0 {
                    let nullifier_key = client::NullifierKey { bytes: fvk.nullifier_key.0 };
                    let nullifier = resource.nullifier(nullifier_key);
                    state.nf_map.insert(nullifier, state.current_pos);
                    state.pos_map.entry(fvk.clone()).or_default().insert(state.current_pos);
                    break;
                }
            }
            state.current_pos += 1;
        }
        // Scan the nullifier in the queue
        for nullifier in pool.nullifier_queue {
            if let Some(pos) = state.nf_map.get(&nullifier) {
                state.spent_notes.insert(*pos);
            }
        }
        state
    }
}

fn add_shielded_input(
    spending_key: ExtendedSpendingKey,
    note: Resource,
) -> (TransferAuthWitness, ConsumedResourceWitness, ResourceLogicInstance) {
    // The value info
    let mut value_info = ValueInfo {
        auth_pk: [0u8; _],
        encryption_pk: [0u8; _],
    };
    let payment_addr = spending_key.to_viewing_key().to_payment_address();
    value_info.auth_pk.copy_from_slice(&payment_addr.verifying_key.to_encoded_point(false).as_bytes());
    value_info.encryption_pk.copy_from_slice(&payment_addr.public_key.to_encoded_point(false).as_bytes());
    // The action root
    let action_root = [0u8; DIGEST_BYTES];
    // Sign over the resource
    let auth_sig: Signature = spending_key.signing_key.sign_prehash(&action_root).expect("unable to sign resource");
    // The transfer authorization witness
    let logic_witness = TransferAuthWitness {
        resource: note.clone(),
        is_consumed: true,
        action_root,
        nullifier_key: Some(client::NullifierKey { bytes: spending_key.nullifier_key.0 }),
        value_info: Some(value_info),
        resource_ciphertext: None,
        resource_ciphertext_len: 0,
        discovery_ciphertext: None,
        discovery_ciphertext_len: 0,
        label_info: None,
        auth_sig: Some(auth_sig.to_bytes().into()),
        forwarder_info: None,
    };
    // Compliance witness
    let compliance_witness = ConsumedResourceWitness {
        resource: logic_witness.resource,
        nf_key: client::NullifierKey { bytes: spending_key.nullifier_key.0 },
        cm_merkle_path: MerklePath {
            path: [(FieldElement::zero(), false); MAX_TREE_DEPTH],
            depth: MAX_TREE_DEPTH as u32,
        },
    };
    let resource_commitment = compliance_witness.resource.commitment();
    let resource_nullifier = compliance_witness.
        resource
        .nullifier_from_commitment(compliance_witness.nf_key, resource_commitment);
    let logic_instance = ResourceLogicInstance {
        tag: resource_nullifier,
        action_root: action_root,
        is_consumed: logic_witness.is_consumed,
        app_data: AppData::default(),
    };
    (logic_witness, compliance_witness, logic_instance)
}

fn add_transparent_input(
    rng: &mut impl Rng,
    logic_ref: [u8; DIGEST_BYTES],
    addr: Address,
    erc20_token_addr: Address,
    amount: u128,
) -> (TransferAuthWitness, ConsumedResourceWitness, ResourceLogicInstance) {
    // Compute the label reference
    let mut label_ref_bytes = [0u8; FORWARDER_ADDR_LEN + ERC20_TOKEN_ADDR_LEN];
    label_ref_bytes[..FORWARDER_ADDR_LEN].copy_from_slice(&ERC20_FORWARDER_ADDRESS.as_slice());
    label_ref_bytes[FORWARDER_ADDR_LEN..].copy_from_slice(erc20_token_addr.as_slice());
    let label_ref = keccak256(label_ref_bytes);
    // The label info
    let label_info = LabelInfo {
        forwarder_addr: ERC20_FORWARDER_ADDRESS.into_array(),
        erc20_token_addr: erc20_token_addr.into_array(),
    };
    // Generate randomness for the construction of the resource
    let mut rand_seed = [0u8; DIGEST_BYTES];
    rng.fill(&mut rand_seed);
    let mut nonce = [0u8; DIGEST_BYTES];
    rng.fill(&mut nonce);
    // Generate a nullifier key
    let nullifier_key = NullifierKey::random(rng);
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
    // Compliance witness
    let compliance_witness = ConsumedResourceWitness {
        resource,
        nf_key: client::NullifierKey { bytes: nullifier_key.0 },
        cm_merkle_path: MerklePath {
            path: [(FieldElement::zero(), false); MAX_TREE_DEPTH],
            depth: MAX_TREE_DEPTH as u32,
        },
    };
    // Encode forwarder calldata
    let (enc_input, enc_len) = encode_wrap_forwarder_input(
        label_info.erc20_token_addr,
        resource.quantity,
        permit_info.permit_nonce,
        permit_info.permit_deadline,
        forwarder_info.ethereum_account_addr,
        action_root,
        permit_info.permit_sig,
    );
    let (data, data_len) = encode_forwarder_calldata(
        label_info.forwarder_addr,
        enc_input,
        [0; MAX_OUTPUT_LEN],
    );
    // Finally, construct the application data
    let mut app_data = AppData::default();
    app_data.external_payload[0] = ExpirableBlob {
        blob: data,
        blob_len: data_len.try_into().expect("data length too large"),
        deletion_criterion: false,
    };
    app_data.external_payload_len = 1;
    let resource_commitment = compliance_witness.resource.commitment();
    let resource_nullifier = compliance_witness.
        resource
        .nullifier_from_commitment(compliance_witness.nf_key, resource_commitment);
    let logic_instance = ResourceLogicInstance {
        tag: resource_nullifier,
        action_root: action_root,
        is_consumed: logic_witness.is_consumed,
        app_data,
    };
    (logic_witness, compliance_witness, logic_instance)
}

fn add_shielded_output(
    rng: &mut impl Rng,
    logic_ref: [u8; DIGEST_BYTES],
    payment_addr: &PaymentAddress,
    erc20_token_addr: Address,
    amount: u128,
    consumed_nullifiers_digest: [u8; DIGEST_BYTES],
    created_count: u8,
) -> (TransferAuthWitness, ResourceLogicInstance) {
    // Compute the label reference
    let mut label_ref_bytes = [0u8; FORWARDER_ADDR_LEN + ERC20_TOKEN_ADDR_LEN];
    label_ref_bytes[..FORWARDER_ADDR_LEN].copy_from_slice(&ERC20_FORWARDER_ADDRESS.as_slice());
    label_ref_bytes[FORWARDER_ADDR_LEN..].copy_from_slice(erc20_token_addr.as_slice());
    let label_ref = keccak256(label_ref_bytes);
    // The label info
    let label_info = LabelInfo {
        forwarder_addr: ERC20_FORWARDER_ADDRESS.into_array(),
        erc20_token_addr: erc20_token_addr.into_array(),
    };
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
    //
    let resource_ciphertext = [0u8; _];
    let resource_ciphertext_len = 0;
    let discovery_ciphertext = [0u8; _];
    let discovery_ciphertext_len = 0;
    // The transfer authorization witness
    let witness = TransferAuthWitness {
        resource,
        is_consumed: false,
        action_root,
        nullifier_key: None,
        value_info: Some(value_info),
        resource_ciphertext: Some(resource_ciphertext),
        resource_ciphertext_len,
        discovery_ciphertext: Some(discovery_ciphertext),
        discovery_ciphertext_len,
        label_info: Some(label_info),
        auth_sig: None,
        forwarder_info: None,
    };
    // Construct the application data
    let mut app_data = AppData::default();
    // Generate resource_payload
    app_data.resource_payload[0] = ExpirableBlob {
        blob: resource_ciphertext,
        blob_len: resource_ciphertext_len,
        deletion_criterion: true,
    };
    app_data.resource_payload_len = 1;
    // Generate discovery_payload
    app_data.discovery_payload[0] = ExpirableBlob {
        blob: discovery_ciphertext,
        blob_len: discovery_ciphertext_len,
        deletion_criterion: true,
    };
    app_data.discovery_payload_len = 1;
    let resource_commitment = witness.resource.commitment();
    // Finally construct the resource logic instance
    let logic_instance = ResourceLogicInstance {
        tag: resource_commitment,
        action_root: action_root,
        is_consumed: witness.is_consumed,
        app_data,
    };
    (witness, logic_instance)
}

fn add_transparent_output(
    rng: &mut impl Rng,
    logic_ref: [u8; DIGEST_BYTES],
    addr: &Address,
    erc20_token_addr: Address,
    amount: u128,
    consumed_nullifiers_digest: [u8; DIGEST_BYTES],
    created_count: u8,
) -> (TransferAuthWitness, ResourceLogicInstance) {
    // Compute the label reference
    let mut label_ref_bytes = [0u8; FORWARDER_ADDR_LEN + ERC20_TOKEN_ADDR_LEN];
    label_ref_bytes[..FORWARDER_ADDR_LEN].copy_from_slice(&ERC20_FORWARDER_ADDRESS.as_slice());
    label_ref_bytes[FORWARDER_ADDR_LEN..].copy_from_slice(erc20_token_addr.as_slice());
    let label_ref = keccak256(label_ref_bytes);
    // The label info
    let label_info = LabelInfo {
        forwarder_addr: ERC20_FORWARDER_ADDRESS.into_array(),
        erc20_token_addr: erc20_token_addr.into_array(),
    };
    // Generate randomness for the construction of the resource
    let mut rand_seed = [0u8; DIGEST_BYTES];
    rng.fill(&mut rand_seed);
    // Generate a nullifier key
    let nullifier_key = NullifierKey::random(rng);
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
    let (enc_input, enc_len) = encode_unwrap_forwarder_input(
        label_info.erc20_token_addr,
        forwarder_info.ethereum_account_addr,
        resource.quantity,
    );
    let (data, data_len) = encode_forwarder_calldata(
        label_info.forwarder_addr,
        enc_input,
        [0; MAX_OUTPUT_LEN],
    );
    // Finally, construct the application data
    let mut app_data = AppData::default();
    app_data.external_payload[0] = ExpirableBlob {
        blob: data,
        blob_len: data_len.try_into().expect("data length too large"),
        deletion_criterion: false,
    };
    app_data.external_payload_len = 1;
    let resource_commitment = witness.resource.commitment();
    let logic_instance = ResourceLogicInstance {
        tag: resource_commitment,
        action_root: action_root,
        is_consumed: witness.is_consumed,
        app_data,
    };
    (witness, logic_instance)
}

// Handle client subcommands
fn handle_client(cli: ClientCommands) -> Result<(), std::io::Error> {
    let wallet_path = Path::new("wallet.toml");
    let pool_state_path = Path::new("pool_state.bin");
    // The state of the shielded pool
    let mut pool_state = if let Ok(state_bytes) = std::fs::read(pool_state_path) {
        PoolState::try_from_slice(&state_bytes)?
    } else {
        PoolState::default()
    };
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
            // The consumed nullifiers
            let mut consumed_nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
            // The consumed data
            let mut consumed_data = [ConsumedResourceWitness::default(); MAX_CONSUMED];
            let mut consumed_count = 0u8;
            // The created data
            let mut created_resources = [Resource::default(); MAX_CREATED];
            let mut created_count = 0u8;
            // Data about transaction change
            let mut change = None;
            // Add transaction inputs
            if store.spending_keys.contains_key(&from) {
                let mut value_acc = 0u128;
                // Obtain the key to authorize the transaction
                let passphrase =
                    prompt_passphrase(&format!("Enter passphrase to decrypt {}: ", from));
                let spending_key = store.decrypt_spending_key(from, passphrase)?;
                // First synchronize the client state
                let client_state = ClientState::synchronize(pool_state.clone(), &[spending_key.to_viewing_key()]);
                let payment_addr = spending_key.to_viewing_key().to_payment_address();
                if let Some(note_positions) = client_state.pos_map.get(&spending_key.to_viewing_key()) {
                    for pos in note_positions {
                        // Only consider notes that have not yet been spent
                        if client_state.spent_notes.contains(pos) || value_acc >= amount.into() {
                            continue;
                        }
                        // Get the note
                        let note = client_state.note_map.get(pos).expect("Missing note");
                        if !(note.logic_ref == logic_ref && note.label_ref == label_ref) {
                            continue;
                        }
                        value_acc += note.quantity;
                        let (logic_witness, compliance_witness, logic_instance) = add_shielded_input(spending_key.clone(), note.clone());
                        consumed_data[usize::from(consumed_count)] = compliance_witness;
                        consumed_nullifiers[usize::from(consumed_count)] = logic_instance.tag;
                        consumed_count += 1;
                        let mut input_map = InputMap::new();
                        input_map.insert("witness".to_string(), logic_witness.into());
                        // Compute the proof from the witness bytes
                        let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                        let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                        println!("Shielded input verification response: {:?}", verify_response);
                        assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
                    }
                }
                // Send the change back to the sender if there's any
                assert!(value_acc >= amount.into());
                if value_acc > amount.into() {
                    change = Some((payment_addr, erc20_token_addr, value_acc - u128::from(amount)));
                }
            } else if let Ok(addr) = store.evaluate_address(&from) {
                let (logic_witness, compliance_witness, logic_instance) = add_transparent_input(
                    &mut rng,
                    logic_ref,
                    addr,
                    erc20_token_addr,
                    amount.into(),
                );
                consumed_data[usize::from(consumed_count)] = compliance_witness;
                consumed_nullifiers[usize::from(consumed_count)] = logic_instance.tag;
                consumed_count += 1;
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), logic_witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Transparent input verification response: {:?}", verify_response);
                assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
            }
            // Compute the digest of the consumed nullifiers
            let consumed_nullifiers_digest = Resource::hash_nullifiers(consumed_nullifiers, consumed_count.into());
            // Add change output
            if let Some((payment_addr, erc20_token_addr, amount)) = change {
                let (witness, logic_instance) = add_shielded_output(
                    &mut rng,
                    logic_ref,
                    &payment_addr,
                    erc20_token_addr,
                    amount,
                    consumed_nullifiers_digest,
                    created_count,
                );
                // Compliance witness
                created_resources[usize::from(created_count)] = witness.resource;
                created_count += 1;
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Change proof verification response: {:?}", verify_response);
                assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
            }
            // Add transaction outputs
            if let Ok(payment_addr) = store.evaluate_payment_address(&to) {
                let (witness, logic_instance) = add_shielded_output(
                    &mut rng,
                    logic_ref,
                    &payment_addr,
                    erc20_token_addr,
                    amount.into(),
                    consumed_nullifiers_digest,
                    created_count,
                );
                // Compliance witness
                created_resources[usize::from(created_count)] = witness.resource;
                created_count += 1;
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Shielded output verification response: {:?}", verify_response);
                assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
            } else if let Ok(addr) = store.evaluate_address(&to) {
                // The transfer authorization witness
                let (witness, logic_instance) = add_transparent_output(
                    &mut rng,
                    logic_ref,
                    &addr,
                    erc20_token_addr,
                    amount.into(),
                    consumed_nullifiers_digest,
                    created_count,
                );
                // Compliance witness
                created_resources[usize::from(created_count)] = witness.resource;
                created_count += 1;
                let mut input_map = InputMap::new();
                input_map.insert("witness".to_string(), witness.into());
                // Compute the proof from the witness bytes
                let prove_response = logic_circuit.circuit_prove(&mut api, input_map).unwrap();
                let verify_response = logic_circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
                println!("Transparent output verification response: {:?}", verify_response);
                assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
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
            println!("Compliance verification response: {:?}", verify_response);
            // Finally update the state of the pool
            for i in 0..consumed_count {
                pool_state.nullifier_queue.push(consumed_nullifiers[usize::from(i)]);
            }
            for i in 0..created_count {
                pool_state.note_queue.push(created_resources[usize::from(i)]);
            }
            // Save the updated state
            let state_bytes = borsh::to_vec(&pool_state)?;
            std::fs::write(pool_state_path, state_bytes)?;
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
