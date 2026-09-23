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
use client::ConsumedResourcePublic;
use barretenberg_rs::Backend;
use alloy::primitives::hex;
use client::CreatedResourcePublic;
use bn254_blackbox_solver::multi_scalar_mul;
use client::ComplianceInstance;
use client::EmbeddedCurvePoint;
use std::ops::{Add, Sub, AddAssign, SubAssign};
use std::cmp::Ordering;
use client::EncryptionInfo;
use wallet::GRUMPKIN_PUBLIC_KEY_LEN;
use client::ENCRYPTION_NONCE_LEN;
use client::ResourceWithLabel;
use client::DISCOVERY_NONCE_LEN;
use k256::SecretKey;
use k256::ecdh::diffie_hellman;
use client::DISCOVERY_PK_LEN;
use client::DISCOVERY_SHARED_POINT_LEN;
use client::Ciphertext;
use barretenberg_rs::generated_types::CircuitProveResponse;
use barretenberg_rs::BarretenbergError;
use client::Commitment;
use std::marker::PhantomData;

// ERC-20 forwarder address
const ERC20_FORWARDER_ADDRESS: Address = address!("0x0A62bE41E66841f693f922991C4e40C89cb0CFDF");
const FORWARDER_ADDR_LEN: usize = 20;
const ERC20_TOKEN_ADDR_LEN: usize = 20;
const MAX_AUTH_PK_LEN: usize = 65;
const MAX_ENCRYPTION_PK_LEN: usize = 64;
const MAX_OUTPUT_LEN: usize = 64;
pub static INITIAL_ROOT: [u8; 32] =
        hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

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

#[derive(Debug)]
enum ShieldedPoolError {
    BarretenbergError(BarretenbergError),
    LogicProof,
    ComplianceProof,
    DuplicateNullifier,
    DuplicateCommitment,
    UnpairedNullifier,
    UnpairedCommitment,
    CircuitNotRegistered,
}

// State of the shielded pool
#[derive(Default, BorshSerialize, BorshDeserialize, Clone)]
struct ShieldedPool {
    // Nullifiers in the pool
    nullifiers: BTreeSet<Nullifier>,
    // Resource commitments in the pool
    commitments: Vec<Commitment>,
    // Transactions in the pool
    transactions: Vec<Transaction>,
    // Registered logic circuits
    #[borsh(skip)]
    logic_circuits: BTreeMap<Vec<u8>, BarretenbergCircuit>,
}

impl ShieldedPool {
    fn register_logic(&mut self, logic_circuit: BarretenbergCircuit) {
        self.logic_circuits.insert(logic_circuit.compute_vk_response.hash.clone(), logic_circuit);
    }

    fn deregister_logic(&mut self, logic_hash: Vec<u8>) -> Option<BarretenbergCircuit> {
        self.logic_circuits.remove(&logic_hash)
    }
    
    fn submit<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        compliance_circuit: &mut BarretenbergCircuit,
        tx: Transaction,
    ) -> Result<(), ShieldedPoolError> {
        // Check the compliance proof
        let compliance_prove_response = CircuitProveResponse {
            proof: tx.compliance_proof,
            public_inputs: vec![tx.compliance_instance.digest().to_be_bytes()],
            vk: compliance_circuit.compute_vk_response.clone(),
        };
        let compliance_verify_response = compliance_circuit
            .circuit_verify(api, compliance_prove_response.clone())
            .map_err(ShieldedPoolError::BarretenbergError)?;
        println!("Compliance proof verification response: {:?}", compliance_verify_response);
        if !compliance_verify_response.verified {
            return Err(ShieldedPoolError::ComplianceProof);
        }
        let mut nullifiers = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        // Track the nullifiers encountered
        for i in 0..tx.compliance_instance.consumed_count {
            let consumed_public = tx.compliance_instance.consumed_publics[i as usize];
            if nullifiers.contains_key(&consumed_public.resource_nullifier) {
                return Err(ShieldedPoolError::DuplicateNullifier);
            } else {
                nullifiers.insert(consumed_public.resource_nullifier, consumed_public.resource_logic_ref);
            }
        }
        // Track the commitments encountered
        for i in 0..tx.compliance_instance.created_count {
            let created_public = tx.compliance_instance.created_publics[i as usize];
            if commitments.contains_key(&created_public.resource_commitment) {
                return Err(ShieldedPoolError::DuplicateCommitment);
            } else {
                commitments.insert(created_public.resource_commitment, created_public.resource_logic_ref);
            }
        }
        // Check all the logic proofs
        for (logic_instance, proof) in &tx.logic_instances {
            // Cross-check the tags and grab the relevant circuit
            let logic_circuit = if logic_instance.is_consumed {
                // Cross-check the nullifiers
                if let Some(hash) = nullifiers.remove(&logic_instance.tag) {
                    self.logic_circuits.get_mut(&hash.to_vec()).ok_or(ShieldedPoolError::CircuitNotRegistered)?
                } else {
                    return Err(ShieldedPoolError::UnpairedNullifier);
                }
            } else {
                // Cross-check the commitments
                if let Some(hash) = commitments.remove(&logic_instance.tag) {
                    self.logic_circuits.get_mut(&hash.to_vec()).ok_or(ShieldedPoolError::CircuitNotRegistered)?
                } else {
                    return Err(ShieldedPoolError::UnpairedCommitment);
                }
            };
            // Verify the proofs
            let prove_response = CircuitProveResponse {
                proof: proof.clone(),
                public_inputs: vec![logic_instance.digest().to_be_bytes()],
                vk: logic_circuit.compute_vk_response.clone(),
            };
            let verify_response = logic_circuit
                .circuit_verify(api, prove_response.clone())
                .map_err(ShieldedPoolError::BarretenbergError)?;
            println!("Logic proof verification response: {:?}", verify_response);
            if !verify_response.verified {
                return Err(ShieldedPoolError::LogicProof);
            }
        }
        // Ensure that there's a logic instance for each tag in the compliance instance
        if !nullifiers.is_empty() {
            return Err(ShieldedPoolError::UnpairedNullifier);
        } else if !commitments.is_empty() {
            return Err(ShieldedPoolError::UnpairedCommitment);
        }
        // Update the nullifier set
        for (logic_instance, _proof) in tx.logic_instances {
            if logic_instance.is_consumed {
                // Handle nullification
                if self.nullifiers.contains(&logic_instance.tag) {
                    return Err(ShieldedPoolError::DuplicateNullifier);
                } else {
                    self.nullifiers.insert(logic_instance.tag);
                }
            } else {
                // Update the Merkle tree
                self.commitments.push(logic_instance.tag);
            }
        }
        Ok(())
    }
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
    fn synchronize(pool: ShieldedPool, fvks: &[ExtendedFullViewingKey]) -> Self {
        let mut state = Self::default();
        // Scan the notes in the queue
        for transaction in pool.transactions {
            for (logic_instance, _) in transaction.logic_instances {
                let app_data = logic_instance.app_data;
                for i in 0..app_data.discovery_payload_len {
                }
            }
            /*state.note_map.insert(state.current_pos, resource);
            for fvk in fvks {
                if resource.nk_commitment == fvk.nullifier_key.commit().0 {
                    let nullifier_key = client::NullifierKey { bytes: fvk.nullifier_key.0 };
                    let nullifier = resource.nullifier(nullifier_key);
                    state.nf_map.insert(nullifier, state.current_pos);
                    state.pos_map.entry(fvk.clone()).or_default().insert(state.current_pos);
                    break;
                }
            }
            state.current_pos += 1;*/
        }
        // Scan the nullifier in the queue
        for nullifier in pool.nullifiers {
            if let Some(pos) = state.nf_map.get(&nullifier) {
                state.spent_notes.insert(*pos);
            }
        }
        state
    }
}

// Representation of a number as sign and magnitude
#[derive(Clone, Copy, Debug)]
struct SignMagnitude<T> {
    // False is a plus sign, true is a negative sign
    sign: bool,
    // Magnitude of the number
    magnitude: T,
}

impl<T> From<T> for SignMagnitude<T> {
    fn from(magnitude: T) -> Self {
        Self { sign: false, magnitude }
    }
}

impl<T: Default> Default for SignMagnitude<T> {
    fn default() -> Self {
        Self { sign: false, magnitude: T::default() }
    }
}

impl<U, T: Add<Output = U> + Sub<Output = U> + Ord> Add for SignMagnitude<T> {
    type Output = SignMagnitude<U>;
    
    fn add(self, rhs: Self) -> Self::Output {
        if self.sign == rhs.sign {
            SignMagnitude::<U> { sign: self.sign, magnitude: self.magnitude + rhs.magnitude }
        } else if self.magnitude >= rhs.magnitude {
            SignMagnitude::<U> { sign: self.sign, magnitude: self.magnitude - rhs.magnitude }
        } else {
            SignMagnitude::<U> { sign: rhs.sign, magnitude: rhs.magnitude - self.magnitude }
        }
    }
}

impl<T: AddAssign + SubAssign + Ord> AddAssign for SignMagnitude<T> {
    fn add_assign(&mut self, mut rhs: Self) {
        if self.sign == rhs.sign {
            self.magnitude += rhs.magnitude;
        } else if self.magnitude >= rhs.magnitude {
            self.magnitude -= rhs.magnitude;
        } else {
            std::mem::swap(self, &mut rhs);
            self.magnitude -= rhs.magnitude;
        }
    }
}

impl<U, T: Add<Output = U> + Sub<Output = U> + Ord> Sub for SignMagnitude<T> {
    type Output = SignMagnitude<U>;
    
    fn sub(self, mut rhs: Self) -> Self::Output {
        rhs.sign = !rhs.sign;
        self + rhs
    }
}

impl<T: AddAssign + SubAssign + Ord> SubAssign for SignMagnitude<T> {
    fn sub_assign(&mut self, mut rhs: Self) {
        rhs.sign = !rhs.sign;
        *self += rhs
    }
}

impl<T: Default + Eq> PartialEq for SignMagnitude<T> {
    fn eq(&self, other: &Self) -> bool {
        let zero = T::default();
        let is_identical = self.sign == other.sign && self.magnitude == other.magnitude;
        let both_zero = self.magnitude == zero && other.magnitude == zero;
        is_identical || both_zero
    }
}

impl<T: Default + Eq> Eq for SignMagnitude<T> {}

impl<T: Default + Eq + Ord> Ord for SignMagnitude<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if *self == *other {
            Ordering::Equal
        } else if self.sign == other.sign && !self.sign {
            self.magnitude.cmp(&other.magnitude)
        } else if self.sign == other.sign {
            self.magnitude.cmp(&other.magnitude).reverse()
        } else if !self.sign {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl<T: Default + Eq + Ord> PartialOrd for SignMagnitude<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
// A resource machine transaction
struct Transaction {
    // Logic instances and their corresponding proofs
    logic_instances: Vec<(ResourceLogicInstance, Vec<Vec<u8>>)>,
    // The compliance instance
    compliance_instance: ComplianceInstance,
    // The compliance proof
    compliance_proof: Vec<Vec<u8>>,
}

// Data structure to facilitate building Transactions
struct TransactionBuilder {
    // The consumed nullifiers
    consumed_nullifiers: [[u8; DIGEST_BYTES]; MAX_CONSUMED],
    // The consumed data
    consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    consumed_logics: [ResourceLogicInstance; MAX_CONSUMED],
    consumed_logic_proofs: [Vec<Vec<u8>>; MAX_CONSUMED],
    consumed_count: u8,
    // The created data
    created_resources: [Resource; MAX_CREATED],
    created_publics: [CreatedResourcePublic; MAX_CREATED],
    created_logics: [ResourceLogicInstance; MAX_CREATED],
    created_logic_proofs: [Vec<Vec<u8>>; MAX_CONSUMED],
    created_count: u8,
    // Quantity delta
    delta_map: BTreeMap<EmbeddedCurvePoint, SignMagnitude<u128>>,
    // Circuits required for building proofs
    logic_circuit: BarretenbergCircuit,
    compliance_circuit: BarretenbergCircuit,
}

impl TransactionBuilder {
    fn new<B: Backend>(api: &mut BarretenbergApi<B>) -> Self {
        // Load up the aggregation circuit from disk
        let logic_program_artifact_path = PathBuf::from(TRANSFER_AUTH_CIRCUIT_PATH);
        // Load up the aggregation circuit from disk
        let logic_circuit = BarretenbergCircuit::new(api, logic_program_artifact_path);
        // Load up the aggregation circuit from disk
        let compliance_program_artifact_path = PathBuf::from(COMPLIANCE_CIRCUIT_PATH);
        // Load up the aggregation circuit from disk
        let compliance_circuit = BarretenbergCircuit::new(api, compliance_program_artifact_path);
        // Use the default initialization on other fields
        Self {
            consumed_nullifiers: Default::default(),
            consumed_data: Default::default(),
            consumed_publics: Default::default(),
            consumed_logics: Default::default(),
            consumed_logic_proofs: Default::default(),
            consumed_count: 0,
            created_resources: Default::default(),
            created_publics: Default::default(),
            created_logics: Default::default(),
            created_logic_proofs: Default::default(),
            created_count: 0,
            delta_map: Default::default(),
            logic_circuit,
            compliance_circuit,
        }
    }

    fn build_label_info(forwarder_addr: &Address, token_addr: &Address) -> (LabelInfo, [u8; DIGEST_BYTES]) {
        // Compute the label reference
        let mut label_ref_bytes = [0u8; FORWARDER_ADDR_LEN + ERC20_TOKEN_ADDR_LEN];
        label_ref_bytes[..FORWARDER_ADDR_LEN].copy_from_slice(forwarder_addr.as_slice());
        label_ref_bytes[FORWARDER_ADDR_LEN..].copy_from_slice(token_addr.as_slice());
        let label_ref = keccak256(label_ref_bytes);
        // The label info
        let label_info = LabelInfo {
            forwarder_addr: forwarder_addr.into_array(),
            erc20_token_addr: token_addr.into_array(),
        };
        (label_info, label_ref.0)
    }

    fn build_shielded_input<B: Backend>(
        api: &mut BarretenbergApi<B>,
        spending_key: ExtendedSpendingKey,
        note: Resource,
    ) -> (TransferAuthWitness, ConsumedResourceWitness, ResourceLogicInstance, ConsumedResourcePublic) {
        // The value info
        let payment_addr = spending_key.to_viewing_key().to_payment_address();
        let value_info = ValueInfo {
            auth_pk: payment_addr.verifying_key.to_encoded_point(false).as_bytes().try_into().unwrap(),
            encryption_pk: payment_addr.encryption_public_key,
        };
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
            encryption_info: None,
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
                depth: MAX_TREE_DEPTH,
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
        let commitment_tree_root = compliance_witness.cm_merkle_path.root(api, resource_commitment);
        let compliance_public = ConsumedResourcePublic {
            resource_nullifier,
            resource_logic_ref: note.logic_ref,
            commitment_tree_root,
        };
        (logic_witness, compliance_witness, logic_instance, compliance_public)
    }

    fn build_transparent_input(
        rng: &mut impl Rng,
        logic_ref: [u8; DIGEST_BYTES],
        addr: Address,
        erc20_token_addr: Address,
        amount: u128,
    ) -> (TransferAuthWitness, ConsumedResourceWitness, ResourceLogicInstance, ConsumedResourcePublic) {
        // Compute the label reference
        let (label_info, label_ref) = Self::build_label_info(&ERC20_FORWARDER_ADDRESS, &erc20_token_addr);
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
            label_ref,
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
            encryption_info: None,
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
                depth: MAX_TREE_DEPTH,
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
        let compliance_public = ConsumedResourcePublic {
            resource_nullifier,
            resource_logic_ref: logic_ref,
            commitment_tree_root: INITIAL_ROOT,
        };
        (logic_witness, compliance_witness, logic_instance, compliance_public)
    }

    // Encrypt the given plaintext with the given key preimage and
    // return the ciphertext and random nonce used
    fn encrypt<B: Backend>(
        api: &mut BarretenbergApi<B>,
        rng: &mut (impl Rng + rand::CryptoRng),
        mut plaintext: Vec<u8>,
        key_preimage: &[u8],
    ) -> (Vec<u8>, [u8; DISCOVERY_NONCE_LEN]) {
        // Generate a nonce
        let mut nonce = [0u8; DISCOVERY_NONCE_LEN];
        rng.try_fill_bytes(&mut nonce)
            .expect("Failed to fill discovery nonce");
        // Pad the nonce
        let mut nonce_padded = [0u8; 16];
        nonce_padded[..DISCOVERY_NONCE_LEN].copy_from_slice(&nonce);
        // Derive the encryption key
        let hash = keccak256(key_preimage);
        // Pad the plaintext
        let remainder = 16 - (plaintext.len() % 16);
        plaintext.resize(plaintext.len() + remainder, remainder as u8);
        // Finally do the encryptiion
        let ciphertext = api.aes_encrypt(&plaintext, &nonce_padded, &hash[..16], plaintext.len() as u32)
            .expect("unable to perform AES encryption")
            .ciphertext;
        (ciphertext, nonce)
    }

    // Pad the given slice to the given array length
    fn pad_slice<const M: usize>(src: &[u8]) -> [u8; M] {
        let mut dest = [0u8; M];
        dest[..src.len()].copy_from_slice(src);
        dest
    }

    fn build_shielded_output<B: Backend>(
        api: &mut BarretenbergApi<B>,
        rng: &mut (impl Rng + rand::CryptoRng),
        logic_ref: [u8; DIGEST_BYTES],
        payment_addr: &PaymentAddress,
        erc20_token_addr: Address,
        amount: u128,
        consumed_nullifiers_digest: [u8; DIGEST_BYTES],
        created_count: u8,
    ) -> (TransferAuthWitness, ResourceLogicInstance, CreatedResourcePublic) {
        // Compute the label reference
        let (label_info, label_ref) = Self::build_label_info(&ERC20_FORWARDER_ADDRESS, &erc20_token_addr);
        // Generate randomness for the construction of the resource
        let mut rand_seed = [0u8; DIGEST_BYTES];
        rng.fill(&mut rand_seed);
        // The value info
        let value_info = ValueInfo {
            auth_pk: payment_addr.verifying_key.to_encoded_point(false).as_bytes().try_into().unwrap(),
            encryption_pk: payment_addr.encryption_public_key,
        };
        // Calculate persistent value reference
        let mut value_ref_bytes = [0; MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PK_LEN];
        value_ref_bytes[..MAX_AUTH_PK_LEN].copy_from_slice(&value_info.auth_pk);
        value_ref_bytes[MAX_AUTH_PK_LEN..].copy_from_slice(&value_info.encryption_pk.to_bytes());
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
            label_ref,
            nk_commitment: payment_addr.nullifier_key_commitment.0,
        };
        let payload_plaintext = ResourceWithLabel {
            resource: resource,
            forwarder_addr: label_info.forwarder_addr,
            erc20_token_addr: label_info.erc20_token_addr,
        }.to_bytes().to_vec();
        // The action root
        let action_root = [0u8; DIGEST_BYTES];
        // Generate discovery ciphertext
        let discovery_sk = SecretKey::random(rng);
        let discovery_shared_point = diffie_hellman(discovery_sk.to_nonzero_scalar(), payment_addr.discovery_public_key.as_affine());
        let mut discovery_concat = [0u8; DISCOVERY_PK_LEN + DISCOVERY_SHARED_POINT_LEN];
        discovery_concat[..DISCOVERY_PK_LEN].copy_from_slice(&payment_addr.discovery_public_key.to_encoded_point(false).as_bytes());
        discovery_concat[DISCOVERY_PK_LEN..].copy_from_slice(&discovery_shared_point.raw_secret_bytes());
        let (discovery_ciphertext, discovery_nonce) = Self::encrypt(api, rng, vec![0u8], &discovery_concat);
        let discovery_ciphertext = Ciphertext {
            cipher: discovery_ciphertext.try_into().unwrap(),
            nonce: discovery_nonce,
            pk: k256::AffinePoint::from(discovery_sk.public_key()),
        }.to_bytes();
        // Generate encryption ciphertext
        let sender_sk = EmbeddedCurveScalar::random(rng);
        let shared_point = value_info.encryption_pk * sender_sk;
        let mut encryption_concat = [0u8; 2*GRUMPKIN_PUBLIC_KEY_LEN];
        encryption_concat[..GRUMPKIN_PUBLIC_KEY_LEN].copy_from_slice(&value_info.encryption_pk.to_bytes());
        encryption_concat[GRUMPKIN_PUBLIC_KEY_LEN..].copy_from_slice(&shared_point.to_bytes());
        let (resource_ciphertext, encryption_nonce) = Self::encrypt(api, rng, payload_plaintext, &encryption_concat);
        let resource_ciphertext = Ciphertext {
            cipher: resource_ciphertext.try_into().unwrap(),
            nonce: encryption_nonce,
            pk: EmbeddedCurvePoint::generator() * sender_sk,
        }.to_bytes();
        let encryption_info = EncryptionInfo {
            discovery_ciphertext: Self::pad_slice(&discovery_ciphertext),
            discovery_ciphertext_len: discovery_ciphertext.len() as u32,
            encryption_nonce,
            sender_sk,
        };
        // The transfer authorization witness
        let witness = TransferAuthWitness {
            resource,
            is_consumed: false,
            action_root,
            nullifier_key: None,
            value_info: Some(value_info),
            encryption_info: Some(encryption_info),
            label_info: Some(label_info),
            auth_sig: None,
            forwarder_info: None,
        };
        // Construct the application data
        let mut app_data = AppData::default();
        // Generate resource_payload
        app_data.resource_payload[0] = ExpirableBlob {
            blob: Self::pad_slice(&resource_ciphertext),
            blob_len: resource_ciphertext.len() as u32,
            deletion_criterion: true,
        };
        app_data.resource_payload_len = 1;
        // Generate discovery_payload
        app_data.discovery_payload[0] = ExpirableBlob {
            blob: Self::pad_slice(&discovery_ciphertext),
            blob_len: discovery_ciphertext.len() as u32,
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
        let compliance_public = CreatedResourcePublic {
            resource_commitment,
            resource_logic_ref: logic_ref,
        };
        (witness, logic_instance, compliance_public)
    }

    fn build_transparent_output(
        rng: &mut impl Rng,
        logic_ref: [u8; DIGEST_BYTES],
        addr: &Address,
        erc20_token_addr: Address,
        amount: u128,
        consumed_nullifiers_digest: [u8; DIGEST_BYTES],
        created_count: u8,
    ) -> (TransferAuthWitness, ResourceLogicInstance, CreatedResourcePublic) {
        // Compute the label reference
        let (label_info, label_ref) = Self::build_label_info(&ERC20_FORWARDER_ADDRESS, &erc20_token_addr);
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
            label_ref,
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
            encryption_info: None,
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
        let compliance_public = CreatedResourcePublic {
            resource_commitment,
            resource_logic_ref: logic_ref,
        };
        (witness, logic_instance, compliance_public)
    }
    
    fn add_input<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        logic_witness: TransferAuthWitness,
        compliance_witness: ConsumedResourceWitness,
        logic_instance: ResourceLogicInstance,
        compliance_public: ConsumedResourcePublic,
    ) {
        self.consumed_data[usize::from(self.consumed_count)] = compliance_witness;
        self.consumed_nullifiers[usize::from(self.consumed_count)] = logic_instance.tag;
        self.consumed_publics[usize::from(self.consumed_count)] = compliance_public;
        self.consumed_logics[usize::from(self.consumed_count)] = logic_instance;
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), logic_witness.into());
        // Compute the proof from the witness bytes
        let prove_response = self.logic_circuit.circuit_prove(api, input_map).unwrap();
        self.consumed_logic_proofs[usize::from(self.consumed_count)] = prove_response.proof;
        assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
        // Accumulate delta
        *self.delta_map.entry(compliance_witness.resource.kind(api)).or_default() += SignMagnitude::from(compliance_witness.resource.quantity);
        self.consumed_count += 1;
    }

    fn add_output<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        witness: TransferAuthWitness,
        logic_instance: ResourceLogicInstance,
        compliance_public: CreatedResourcePublic,
    ) {
        // Accumulate delta
        *self.delta_map.entry(witness.resource.kind(api)).or_default() -= SignMagnitude::from(witness.resource.quantity);
        // Compliance witness
        self.created_resources[usize::from(self.created_count)] = witness.resource;
        self.created_publics[usize::from(self.created_count)] = compliance_public;
        self.created_logics[usize::from(self.created_count)] = logic_instance;
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), witness.into());
        // Compute the proof from the witness bytes
        let prove_response = self.logic_circuit.circuit_prove(api, input_map).unwrap();
        self.created_logic_proofs[usize::from(self.created_count)] = prove_response.proof;
        assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
        self.created_count += 1;
    }

    fn build_compliance_artifacts(&self, rng: &mut impl Rng) -> (ComplianceWitness, ComplianceInstance) {
        // Construct the compliance witness
        let compliance_witness = ComplianceWitness {
            consumed_data: self.consumed_data,
            consumed_count: self.consumed_count.into(),
            created_resources: self.created_resources,
            created_count: self.created_count.into(),
            ephemeral_root: INITIAL_ROOT,
            rcv: EmbeddedCurveScalar::random(rng),
        };
        // Sum the deltas
        let mut points = vec![FieldElement::zero(); self.delta_map.len() * 2];
        let mut scalars_lo = vec![FieldElement::zero(); self.delta_map.len()];
        let mut scalars_hi = vec![FieldElement::zero(); self.delta_map.len()];
        for (idx, (point, quantity)) in self.delta_map.iter().enumerate() {
            let signed_point = if *quantity >= SignMagnitude::default() { *point } else { -*point };
            points[2*idx] = signed_point.x;
            points[2*idx + 1] = signed_point.y;
            scalars_lo[idx] = quantity.magnitude.into();
        }
        // Add the value commitment randomness
        let generator = EmbeddedCurvePoint::generator();
        points.push(generator.x);
        points.push(generator.y);
        scalars_lo.push(compliance_witness.rcv.lo);
        scalars_hi.push(compliance_witness.rcv.hi);
        // Compute the delta from all inputs and outputs
        let delta = multi_scalar_mul(&points, &scalars_lo, &scalars_hi)
            .expect("unable to do multi-scalar multiplication");
        let compliance_instance = ComplianceInstance {
            consumed_publics: self.consumed_publics,
            consumed_count: self.consumed_count.into(),
            created_publics: self.created_publics,
            created_count: self.created_count.into(),
            delta: EmbeddedCurvePoint { x: delta.0, y: delta.1 },
        };
        (compliance_witness, compliance_instance)
    }

    fn build<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        compliance_witness: ComplianceWitness,
        compliance_instance: ComplianceInstance,
    ) -> Transaction {
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), compliance_witness.into());
        // Compute the proof from the witness bytes
        let prove_response = self.compliance_circuit.circuit_prove(api, input_map).unwrap();
        assert_eq!(prove_response.public_inputs[0].clone(), compliance_instance.digest().to_be_bytes());
        let mut logic_instances = vec![];
        for idx in 0..usize::from(self.consumed_count) {
            logic_instances.push((self.consumed_logics[idx], self.consumed_logic_proofs[idx].clone()));
        }
        for idx in 0..usize::from(self.created_count) {
            logic_instances.push((self.created_logics[idx], self.created_logic_proofs[idx].clone()));
        }
        Transaction {
            logic_instances,
            compliance_instance,
            compliance_proof: prove_response.proof,
        }
    }
}

// Handle client subcommands
fn handle_client(cli: ClientCommands) -> Result<(), std::io::Error> {
    let wallet_path = Path::new("wallet.toml");
    let pool_state_path = Path::new("pool_state.bin");
    // Use the FFI backend which links directly to static libraries
    let backend = FfiBackend::new().unwrap();
    // Initialize the Barretenberg API
    let mut api = BarretenbergApi::new(backend);
    // The state of the shielded pool
    let mut shielded_pool = if let Ok(state_bytes) = std::fs::read(pool_state_path) {
        ShieldedPool::try_from_slice(&state_bytes)?
    } else {
        ShieldedPool::default()
    };
    // Load up the transfer authorization circuit from disk
    let logic_program_artifact_path = PathBuf::from(TRANSFER_AUTH_CIRCUIT_PATH);
    let logic_circuit = BarretenbergCircuit::new(&mut api, logic_program_artifact_path);
    // Register the transfer authorization circuit with the shielded pool
    shielded_pool.register_logic(logic_circuit);
    // Attempt to load the wallet, or default to empty if it doesn't exist
    let store = Store::load(wallet_path).unwrap_or_default();
    let mut rng = rand::thread_rng();
    match cli {
        ClientCommands::Transfer { rpc, from, to, token, amount, pool, signer } => {
            let mut builder = TransactionBuilder::new(&mut api);
            // The resource logic reference is the UltraHonk verification key hash
            let logic_ref = builder.logic_circuit
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
                let client_state = ClientState::synchronize(shielded_pool.clone(), &[spending_key.to_viewing_key()]);
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
                        let (logic_witness, compliance_witness, logic_instance, compliance_public) =
                            TransactionBuilder::build_shielded_input(&mut api, spending_key.clone(), note.clone());
                        builder.add_input(&mut api, logic_witness, compliance_witness, logic_instance, compliance_public);
                    }
                }
                // Send the change back to the sender if there's any
                assert!(value_acc >= amount.into());
                if value_acc > amount.into() {
                    change = Some((payment_addr, erc20_token_addr, value_acc - u128::from(amount)));
                }
            } else if let Ok(addr) = store.evaluate_address(&from) {
                let (logic_witness, compliance_witness, logic_instance, compliance_public) = TransactionBuilder::build_transparent_input(
                    &mut rng,
                    logic_ref,
                    addr,
                    erc20_token_addr,
                    amount.into(),
                );
                builder.add_input(&mut api, logic_witness, compliance_witness, logic_instance, compliance_public);
            }
            // Compute the digest of the consumed nullifiers
            let consumed_nullifiers_digest = Resource::hash_nullifiers(builder.consumed_nullifiers, builder.consumed_count.into());
            // Add change output
            if let Some((payment_addr, erc20_token_addr, amount)) = change {
                let (witness, logic_instance, compliance_public) = TransactionBuilder::build_shielded_output(
                    &mut api,
                    &mut rng,
                    logic_ref,
                    &payment_addr,
                    erc20_token_addr,
                    amount,
                    consumed_nullifiers_digest,
                    builder.created_count,
                );
                builder.add_output(&mut api, witness, logic_instance, compliance_public);
            }
            // Add transaction outputs
            if let Ok(payment_addr) = store.evaluate_payment_address(&to) {
                let (witness, logic_instance, compliance_public) = TransactionBuilder::build_shielded_output(
                    &mut api,
                    &mut rng,
                    logic_ref,
                    &payment_addr,
                    erc20_token_addr,
                    amount.into(),
                    consumed_nullifiers_digest,
                    builder.created_count,
                );
                builder.add_output(&mut api, witness, logic_instance, compliance_public);
            } else if let Ok(addr) = store.evaluate_address(&to) {
                // The transfer authorization witness
                let (witness, logic_instance, compliance_public) = TransactionBuilder::build_transparent_output(
                    &mut rng,
                    logic_ref,
                    &addr,
                    erc20_token_addr,
                    amount.into(),
                    consumed_nullifiers_digest,
                    builder.created_count,
                );
                builder.add_output(&mut api, witness, logic_instance, compliance_public);
            }
            let (compliance_witness, compliance_instance) = builder.build_compliance_artifacts(&mut rng);
            // Finally build the transaction
            let transaction = builder.build(&mut api, compliance_witness, compliance_instance);
            shielded_pool
                .submit(&mut api, &mut builder.compliance_circuit, transaction)
                .expect("Transaction validation failed");
            // Save the updated state
            let state_bytes = borsh::to_vec(&shielded_pool)?;
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
