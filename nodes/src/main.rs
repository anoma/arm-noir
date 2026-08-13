pub mod aggregator;

use acir::AcirField;
use crate::aggregator::BarretenbergAggregator;
use std::ops::RangeFrom;
use crate::aggregator::RecursiveAggregator;
use crate::aggregator::VerifierInputs;
use crate::aggregator::ThreadedAggregator;
use crate::aggregator::TcpAggregatorServer;
use crate::aggregator::Aggregator;
use std::net::ToSocketAddrs;
use nodes::init_srs;
use clap::{Parser, Args};
use noirc_abi::InputMap;
use noirc_abi::input_parser::InputValue;
use acir::FieldElement;
use serde::{Deserialize, Serialize};

const DIGEST_BYTES: usize = 32;
// Constants for bounding unbounded loops and variable-length arrays
const MAX_FORWARDER_ADDR_LEN: usize = 20;
const MAX_ERC20_TOKEN_ADDR_LEN: usize = 20;
const MAX_ETH_ADDR_LEN: usize = 20;
const MAX_AUTH_PK_LEN: usize = 65;
const MAX_ENCRYPTION_PK_LEN: usize = 65;
const MAX_AUTH_SIG_LEN: usize = 64;
const MAX_RESOURCE_CIPHERTEXT_LEN: usize = 340;
const MAX_DISCOVERY_CIPHERTEXT_LEN: usize = 340;
const MAX_PERMIT_NONCE_LEN: usize = 32;
const MAX_PERMIT_DEADLINE_LEN: usize = 32;
const MAX_PERMIT_SIG_LEN: usize = 65;
const MAX_INPUT_LEN: u32 = 256;
const MAX_OUTPUT_LEN: u32 = 64;
const MAX_FORWARDER_CALLDATA_LEN: u32 = 340;
const MAX_BLOBS_PER_PAYLOAD: u32 = 1;
const MAX_BLOB_LEN: u32 = 340;
const MAX_LOGIC_DIGEST_BUF_LEN: u32 = 1461;
const CALL_TYPE_WRAP: u8 = 0;
const CALL_TYPE_UNWRAP: u8 = 1;
const PRF_EXPAND_PERSONALIZATION_LEN: u32 = 16;

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

fn bytes_to_input_value(bytes: &[u8]) -> InputValue {
    InputValue::Vec(
        bytes
            .into_iter()
            .map(|x| InputValue::Field(FieldElement::from(*x)))
            .collect(),
    )
}

/// ARM Resource
#[derive(Deserialize, Serialize)]
pub struct Resource {
    /// a succinct representation of the predicate associated with the resource
    pub logic_ref: [u8; DIGEST_BYTES],
    /// specifies the fungibility domain for the resource
    pub label_ref: [u8; DIGEST_BYTES],
    /// the fungible value reference of the resource
    pub value_ref: [u8; DIGEST_BYTES],
    /// number representing the quantity of the resource
    pub quantity: u128,
    /// guarantees the uniqueness of the resource computable components
    pub nonce: [u8; DIGEST_BYTES],
    /// commitment to nullifier key
    pub nk_commitment: [u8; DIGEST_BYTES],
    /// flag that reflects the resource ephemerality
    pub is_ephemeral: bool,
    /// randomness seed used to derive whatever randomness needed
    pub rand_seed: [u8; DIGEST_BYTES],
}

impl From<Resource> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: Resource) -> Self {
        let mut map = InputMap::new();
        map.insert("logic_ref".to_string(), bytes_to_input_value(&res.logic_ref));
        map.insert("label_ref".to_string(), bytes_to_input_value(&res.label_ref));
        map.insert("value_ref".to_string(), bytes_to_input_value(&res.value_ref));
        map.insert("nonce".to_string(), bytes_to_input_value(&res.nonce));
        map.insert("nk_commitment".to_string(), bytes_to_input_value(&res.nk_commitment));
        map.insert("rand_seed".to_string(), bytes_to_input_value(&res.rand_seed));
        map.insert("is_ephemeral".to_string(), InputValue::Field(FieldElement::from(res.is_ephemeral)));
        map.insert("quantity".to_string(), InputValue::Field(FieldElement::from(res.quantity)));
        InputValue::Struct(map)
    }
}

/// Nullifier key
pub struct NullifierKey {
    pub bytes: [u8; DIGEST_BYTES],
}

impl From<NullifierKey> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: NullifierKey) -> Self {
        let mut map = InputMap::new();
        map.insert("bytes".to_string(), bytes_to_input_value(&res.bytes));
        InputValue::Struct(map)
    }
}

/// ValueInfo holds information about value plaintext
pub struct ValueInfo {
    /// The authorization verifying key corresponds to the resource.value.owner
    auth_pk: [u8; MAX_AUTH_PK_LEN],
    /// Public key. Obtain from the receiver for persistent resource_ciphertext
    encryption_pk: [u8; MAX_ENCRYPTION_PK_LEN],
}

impl From<ValueInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ValueInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("auth_pk".to_string(), bytes_to_input_value(&res.auth_pk));
        map.insert("encryption_pk".to_string(), bytes_to_input_value(&res.encryption_pk));
        InputValue::Struct(map)
    }
}

/// LabelInfo holds information about label plaintext.
struct LabelInfo {
    /// Address of the forwarder contract for this resource.
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    /// Address of the wrapped token within this resource (e.g. USDC).
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
}

impl From<LabelInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: LabelInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("forwarder_addr".to_string(), bytes_to_input_value(&res.forwarder_addr));
        map.insert("erc20_token_addr".to_string(), bytes_to_input_value(&res.erc20_token_addr));
        InputValue::Struct(map)
    }
}

/// The PermitInfo contains information about the permit2 signature that is used to generate
/// logic proofs over resources.
struct PermitInfo {
    /// Nonce of the permit2 signature.
    permit_nonce: [u8; MAX_PERMIT_NONCE_LEN],
    /// Deadline of the permit2 signature (i.e., when does it expire)
    permit_deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    /// Signature
    permit_sig: [u8; MAX_PERMIT_SIG_LEN],
}

impl From<PermitInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: PermitInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("permit_nonce".to_string(), bytes_to_input_value(&res.permit_nonce));
        map.insert("permit_deadline".to_string(), bytes_to_input_value(&res.permit_deadline));
        map.insert("permit_sig".to_string(), bytes_to_input_value(&res.permit_sig));
        InputValue::Struct(map)
    }
}

/// ForwarderInfo holds information about the forwarder contract being used by a transaction.
struct ForwarderInfo {
    /// Wrapping/Unwrapping of a resource (i.e., mint/burn).
    call_type: u8,
    /// Address of the ethereum account
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    /// PermitInfo (see struct)
    permit: Option<PermitInfo>,
}

impl From<ForwarderInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ForwarderInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("ethereum_account_addr".to_string(), bytes_to_input_value(&res.ethereum_account_addr));
        map.insert("call_type".to_string(), InputValue::Field(FieldElement::from(res.call_type)));
        if let Some(permit) = res.permit {
            map.insert("permit".to_string(), permit.into());
        }
        InputValue::Struct(map)
    }
}

/// The TokenTransferWitness holds all the information necessary to generate a proof of the
/// resource logic of a given resource.
struct TransferAuthWitness {
    /// Resource this witness is about.
    resource: Resource,
    /// Is this a consumed or created resource.
    is_consumed: bool,
    /// Action tree root
    action_root: [u8; DIGEST_BYTES],
    /// Nullifier key for the resource.
    nullifier_key: Option<NullifierKey>,
    /// See ValueInfo struct.
    value_info: Option<ValueInfo>,
    /// A consumed persistent resource requires an authorization signature
    auth_sig: Option<[u8; MAX_AUTH_SIG_LEN]>,
    /// See EncryptionInfo struct.
    resource_ciphertext: Option<[u8; MAX_RESOURCE_CIPHERTEXT_LEN]>,
    resource_ciphertext_len: u32,
    /// The discovery ciphertext for the resource
    discovery_ciphertext: Option<[u8; MAX_DISCOVERY_CIPHERTEXT_LEN]>,
    discovery_ciphertext_len: u32,
    /// See LabelInfo struct.
    label_info: Option<LabelInfo>,
    /// See ForwarderInfo struct.
    forwarder_info: Option<ForwarderInfo>,
}

impl From<TransferAuthWitness> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: TransferAuthWitness) -> Self {
        let mut map = InputMap::new();
        map.insert("resource".to_string(), res.resource.into());
        map.insert("is_consumed".to_string(), InputValue::Field(FieldElement::from(res.is_consumed)));
        map.insert("resource_ciphertext_len".to_string(), InputValue::Field(FieldElement::from(res.resource_ciphertext_len)));
        map.insert("discovery_ciphertext_len".to_string(), InputValue::Field(FieldElement::from(res.discovery_ciphertext_len)));
        map.insert("action_root".to_string(), bytes_to_input_value(&res.action_root));
        if let Some(auth_sig) = res.auth_sig {
            map.insert("auth_sig".to_string(), bytes_to_input_value(&auth_sig));
        }
        if let Some(resource_ciphertext) = res.resource_ciphertext {
            map.insert("resource_ciphertext".to_string(), bytes_to_input_value(&resource_ciphertext));
        }
        if let Some(discovery_ciphertext) = res.discovery_ciphertext {
            map.insert("discovery_ciphertext".to_string(), bytes_to_input_value(&discovery_ciphertext));
        }
        if let Some(nullifier_key) = res.nullifier_key {
            map.insert("nullifier_key".to_string(), nullifier_key.into());
        }
        if let Some(value_info) = res.value_info {
            map.insert("value_info".to_string(), value_info.into());
        }
        if let Some(label_info) = res.label_info {
            map.insert("label_info".to_string(), label_info.into());
        }
        if let Some(forwarder_info) = res.forwarder_info {
            map.insert("forwarder_info".to_string(), forwarder_info.into());
        }
        InputValue::Struct(map)
    }
}

/// CLI interface for the UltraHonk based Anoma Resource Machine
#[derive(Parser)]
#[command(name = "nodes", version, about, long_about = None)]
enum Cli {
    /// Run the proof aggregator
    Aggregator(AggregatorArgs),
    /// Run the transfer client
    Client,
}

#[derive(Args)]
struct AggregatorArgs {
    /// The address at which the aggregator server will run
    address: String,
    /// Number of aggregator threads to run
    thread_count: usize,
}

/// Run the aggregator
fn main() {
    let cli = Cli::parse();
    // Initialize the structured reference string
    init_srs();
    // Process CLI arguments
    match cli {
        Cli::Aggregator(args) => {
            // Finally, start the aggregator server
            aggregator_server(&args.address, args.thread_count);
        },
        Cli::Client => {
            let transfer_auth = TransferAuthWitness {
                action_root: [0; DIGEST_BYTES],
                is_consumed: true,
                nullifier_key: Some(NullifierKey {
                    bytes: [0; DIGEST_BYTES],
                }),
                value_info: Some(ValueInfo {
                    auth_pk: [0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8],
                    encryption_pk: [0; MAX_ENCRYPTION_PK_LEN],
                }),
                auth_sig: Some([
                    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
                    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
                ]),
                resource_ciphertext: Some([0; MAX_RESOURCE_CIPHERTEXT_LEN]),
                resource_ciphertext_len: 0,
                discovery_ciphertext: Some([0; MAX_DISCOVERY_CIPHERTEXT_LEN]),
                discovery_ciphertext_len: 0,
                forwarder_info: Some(ForwarderInfo {
                    call_type: 0,
                    ethereum_account_addr: [0; MAX_ETH_ADDR_LEN],
                    permit: Some(PermitInfo {
                        permit_nonce: [0; MAX_PERMIT_NONCE_LEN],
                        permit_deadline: [0; MAX_PERMIT_DEADLINE_LEN],
                        permit_sig: [0; MAX_PERMIT_SIG_LEN],
                    }),
                }),
                label_info: Some(LabelInfo {
                    forwarder_addr: [0; MAX_FORWARDER_ADDR_LEN],
                    erc20_token_addr: [0; MAX_ERC20_TOKEN_ADDR_LEN],
                }),
                resource: Resource {
                    logic_ref: [0; DIGEST_BYTES],
                    label_ref: [0; DIGEST_BYTES],
                    value_ref: [
                        251, 115, 230, 34, 134, 135, 66, 60, 171, 246, 65, 210, 213, 104, 205, 204,
                        207, 125, 253, 189, 44, 24, 199, 126, 89, 234, 46, 24, 182, 164, 120, 101,
                    ],
                    quantity: 0,
                    nonce: [0; DIGEST_BYTES],
                    nk_commitment: [
                        41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200,
                        75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99,
                    ],
                    is_ephemeral: false,
                    rand_seed: [0; DIGEST_BYTES],
                },
            };
            let mut inputs = InputMap::new();
            inputs.insert("witness".to_string(), transfer_auth.into());
        },
    }
}
