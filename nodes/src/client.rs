use noirc_abi::InputMap;
use noirc_abi::input_parser::InputValue;
use acir::FieldElement;
use serde::{Deserialize, Serialize};

/// Path to file containing the aggregation circuit
pub const TRANSFER_AUTH_CIRCUIT_PATH: &str = "../circuits/target/transfer_auth.json";
// You may need to define this constant at the top of your file alongside TRANSFER_AUTH_CIRCUIT_PATH
const COMPLIANCE_CIRCUIT_PATH: &str = "../circuits/target/compliance.json";
// You may need to define this constant at the top of your file alongside DELTA_VERIFY_CIRCUIT_PATH
const DELTA_VERIFY_CIRCUIT_PATH: &str = "../circuits/target/delta_verify.json";

pub const DIGEST_BYTES: usize = 32;
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
const MAX_CREATED: usize = 4;
const MAX_CONSUMED: usize = 4;
const MAX_KINDS: u32 = 8;
const MAX_TREE_DEPTH: usize = 32; // Set this to your actual max commitment tree depth
const CONSUMED_COUNT_BYTES: u32 = 4;
const CREATED_COUNT_BYTES: u32 = 4;
const BASE_FIELD_BYTES: u32 = 32;
//const MAX_COMPLIANCE_DIGEST_BUF_LEN: u32 = 3*DIGEST_BYTES*MAX_CONSUMED + 2*DIGEST_BYTES*MAX_CREATED + CONSUMED_COUNT_BYTES + CREATED_COUNT_BYTES + 2*BASE_FIELD_BYTES;

/// Construct input value from Option type
fn option_to_input_value<T>(opt: Option<T>) -> InputValue where InputValue: From<T>, T: Default {
    let mut map = InputMap::new();
    map.insert("_is_some".to_string(), InputValue::Field(FieldElement::from(opt.is_some())));
    map.insert("_value".to_string(), opt.unwrap_or_default().into());
    InputValue::Struct(map)
}

/// Array type wrapper that eases construction of InputValues
struct Array<const N: usize>([u8; N]);

impl<const N: usize> From<Array<N>> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: Array<N>) -> Self {
        InputValue::Vec(
            res.0
                .into_iter()
                .map(|x| InputValue::Field(FieldElement::from(x)))
                .collect(),
        )
    }
}

impl<const N: usize> Default for Array<N> {
    fn default() -> Self {
        Self([0; _])
    }
}

/// ARM Resource
#[derive(Deserialize, Serialize, Clone, Copy)]
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
        map.insert("logic_ref".to_string(), Array(res.logic_ref).into());
        map.insert("label_ref".to_string(), Array(res.label_ref).into());
        map.insert("value_ref".to_string(), Array(res.value_ref).into());
        map.insert("nonce".to_string(), Array(res.nonce).into());
        map.insert("nk_commitment".to_string(), Array(res.nk_commitment).into());
        map.insert("rand_seed".to_string(), Array(res.rand_seed).into());
        map.insert("is_ephemeral".to_string(), InputValue::Field(FieldElement::from(res.is_ephemeral)));
        map.insert("quantity".to_string(), InputValue::Field(FieldElement::from(res.quantity)));
        InputValue::Struct(map)
    }
}

/// Nullifier key
#[derive(Default, Clone, Copy)]
pub struct NullifierKey {
    pub bytes: [u8; DIGEST_BYTES],
}

impl From<NullifierKey> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: NullifierKey) -> Self {
        let mut map = InputMap::new();
        map.insert("bytes".to_string(), Array(res.bytes).into());
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

impl Default for ValueInfo {
    fn default() -> Self {
        Self {
            auth_pk: [0; _],
            encryption_pk: [0; _],
        }
    }
}

impl From<ValueInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ValueInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("auth_pk".to_string(), Array(res.auth_pk).into());
        map.insert("encryption_pk".to_string(), Array(res.encryption_pk).into());
        InputValue::Struct(map)
    }
}

/// LabelInfo holds information about label plaintext.
#[derive(Default)]
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
        map.insert("forwarder_addr".to_string(), Array(res.forwarder_addr).into());
        map.insert("erc20_token_addr".to_string(), Array(res.erc20_token_addr).into());
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

impl Default for PermitInfo {
    fn default() -> Self {
        Self {
            permit_nonce: [0; _],
            permit_deadline: [0; _],
            permit_sig: [0; _],
        }
    }
}

impl From<PermitInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: PermitInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("permit_nonce".to_string(), Array(res.permit_nonce).into());
        map.insert("permit_deadline".to_string(), Array(res.permit_deadline).into());
        map.insert("permit_sig".to_string(), Array(res.permit_sig).into());
        InputValue::Struct(map)
    }
}

/// ForwarderInfo holds information about the forwarder contract being used by a transaction.
#[derive(Default)]
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
        map.insert("ethereum_account_addr".to_string(), Array(res.ethereum_account_addr).into());
        map.insert("call_type".to_string(), InputValue::Field(FieldElement::from(res.call_type)));
        map.insert("permit".to_string(), option_to_input_value(res.permit));
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
        map.insert("action_root".to_string(), Array(res.action_root).into());
        map.insert("auth_sig".to_string(), option_to_input_value(res.auth_sig.map(Array)));
        map.insert("resource_ciphertext".to_string(), option_to_input_value(res.resource_ciphertext.map(Array)));
        map.insert("discovery_ciphertext".to_string(), option_to_input_value(res.discovery_ciphertext.map(Array)));
        map.insert("nullifier_key".to_string(), option_to_input_value(res.nullifier_key));
        map.insert("value_info".to_string(), option_to_input_value(res.value_info));
        map.insert("label_info".to_string(), option_to_input_value(res.label_info));
        map.insert("forwarder_info".to_string(), option_to_input_value(res.forwarder_info));
        InputValue::Struct(map)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Copy)]
struct MerklePath {
    path: [(FieldElement, bool); MAX_TREE_DEPTH],
    depth: u32, // Logical length of the path (since the array is statically sized)
}

impl From<MerklePath> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: MerklePath) -> Self {
        let mut map = InputMap::new();
        map.insert("depth".to_string(), InputValue::Field(res.depth.into()));
        map.insert("path".to_string(), InputValue::Vec(
            res.path.into_iter().map(|(x, y)| InputValue::Vec(vec![
                InputValue::Field(x),
                InputValue::Field(y.into()),
            ])).collect()
        ));
        InputValue::Struct(map)
    }
}

/// Private information related to a consumed resource.
#[derive(Clone, Copy)]
struct ConsumedResourceWitness {
    /// The consumed resource.
    resource: Resource,
    /// The path from the consumed commitment to the root of the commitment tree.
    cm_merkle_path: MerklePath,
    /// Nullifier key of the consumed resource.
    nf_key: NullifierKey,
}

impl From<ConsumedResourceWitness> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ConsumedResourceWitness) -> Self {
        let mut map = InputMap::new();
        map.insert("resource".to_string(), res.resource.into());
        map.insert("cm_merkle_path".to_string(), res.cm_merkle_path.into());
        map.insert("nf_key".to_string(), res.nf_key.into());
        InputValue::Struct(map)
    }
}

/// Public information of consumed resources.
struct ConsumedResourcePublic {
    /// The nullifier of the consumed [Resource].
    resource_nullifier: [u8; DIGEST_BYTES],
    /// The logic reference of the consumed [Resource].
    resource_logic_ref: [u8; DIGEST_BYTES],
    /// The root of the Merkle tree where the resource commitment is in.
    commitment_tree_root: [u8; DIGEST_BYTES],
}

impl From<ConsumedResourcePublic> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ConsumedResourcePublic) -> Self {
        let mut map = InputMap::new();
        map.insert("resource_nullifier".to_string(), Array(res.resource_nullifier).into());
        map.insert("resource_logic_ref".to_string(), Array(res.resource_logic_ref).into());
        map.insert("commitment_tree_root".to_string(), Array(res.commitment_tree_root).into());
        InputValue::Struct(map)
    }
}

/// Public information of created resources.
struct CreatedResourcePublic {
    /// The commitment to the created [Resource].
    resource_commitment: [u8; DIGEST_BYTES],
    /// The logic reference of the created [Resource].
    resource_logic_ref: [u8; DIGEST_BYTES],
}

impl From<CreatedResourcePublic> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: CreatedResourcePublic) -> Self {
        let mut map = InputMap::new();
        map.insert("resource_commitment".to_string(), Array(res.resource_commitment).into());
        map.insert("resource_logic_ref".to_string(), Array(res.resource_logic_ref).into());
        InputValue::Struct(map)
    }
}

/// A point on the embedded elliptic curve
/// By definition, the base field of the embedded curve is the scalar field of the proof system curve, i.e the Noir Field.
/// x and y denotes the Weierstrass coordinates of the point.
pub struct EmbeddedCurvePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl From<EmbeddedCurvePoint> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: EmbeddedCurvePoint) -> Self {
        let mut map = InputMap::new();
        map.insert("x".to_string(), InputValue::Field(res.x.into()));
        map.insert("y".to_string(), InputValue::Field(res.y.into()));
        InputValue::Struct(map)
    }
}

/// The compliance instance contains all public inputs to the compliance proof.
struct ComplianceInstance {
    /// Public information of consumed resources
    consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    consumed_count: u32,
    /// Public information of created resources
    created_publics: [CreatedResourcePublic; MAX_CREATED],
    created_count: u32,
    /// The delta coordinates of the created resource
    delta: EmbeddedCurvePoint,
}

impl From<ComplianceInstance> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ComplianceInstance) -> Self {
        let mut map = InputMap::new();
        map.insert("consumed_publics".to_string(), InputValue::Vec(res.consumed_publics.into_iter().map(InputValue::from).collect()));
        map.insert("consumed_count".to_string(), InputValue::Field(res.consumed_count.into()));
        map.insert("created_publics".to_string(), InputValue::Vec(res.created_publics.into_iter().map(InputValue::from).collect()));
        map.insert("created_count".to_string(), InputValue::Field(res.created_count.into()));
        map.insert("delta".to_string(), res.delta.into());
        InputValue::Struct(map)
    }
}

/// Scalar for the embedded curve represented as low and high limbs
/// By definition, the scalar field of the embedded curve is base field of the proving system curve.
/// It may not fit into a Field element, so it is represented with two Field elements; its low and high limbs.
pub struct EmbeddedCurveScalar {
    pub lo: FieldElement,
    pub hi: FieldElement,
}

impl From<EmbeddedCurveScalar> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: EmbeddedCurveScalar) -> Self {
        let mut map = InputMap::new();
        map.insert("lo".to_string(), InputValue::Field(res.lo.into()));
        map.insert("hi".to_string(), InputValue::Field(res.hi.into()));
        InputValue::Struct(map)
    }
}

/// The compliance witness contains all private inputs to the compliance proof.
struct ComplianceWitness {
    /// Private information of consumed resources
    consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    consumed_count: u32,
    /// Private information of created resources
    created_resources: [Resource; MAX_CREATED],
    created_count: u32,
    /// The existing root for ephemeral resources
    ephemeral_root: [u8; DIGEST_BYTES],
    /// Bytes of randomness for the delta commitment `rcv`
    rcv: EmbeddedCurveScalar, // Scalar parsed to field
}

impl From<ComplianceWitness> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ComplianceWitness) -> Self {
        let mut map = InputMap::new();
        map.insert("consumed_data".to_string(), InputValue::Vec(res.consumed_data.into_iter().map(InputValue::from).collect()));
        map.insert("consumed_count".to_string(), InputValue::Field(res.consumed_count.into()));
        map.insert("created_resources".to_string(), InputValue::Vec(res.created_resources.into_iter().map(InputValue::from).collect()));
        map.insert("created_count".to_string(), InputValue::Field(res.created_count.into()));
        map.insert("ephemeral_root".to_string(), Array(res.ephemeral_root).into());
        map.insert("rcv".to_string(), res.rcv.into());
        InputValue::Struct(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use barretenberg_rs::backends::FfiBackend;
    use barretenberg_rs::BarretenbergApi;
    use nodes::BarretenbergCircuit;
    use nodes::init_srs;

    #[test]
    fn test_transfer_auth_witness() {
        // Initialize the structured reference string
        init_srs();
        // Transfer authorization witness
        let transfer_auth = TransferAuthWitness {
            action_root: [0; DIGEST_BYTES],
            is_consumed: true,
            nullifier_key: Some(NullifierKey {
                bytes: [0; DIGEST_BYTES],
            }),
            value_info: Some(ValueInfo {
                auth_pk: [
                    0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
                    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
                    0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
                    0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
                ],
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
        // Construct inputs for proving
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), transfer_auth.into());
        // Load up the aggregation circuit from disk
        let program_artifact_path = PathBuf::from(TRANSFER_AUTH_CIRCUIT_PATH);
        // Use the FFI backend which links directly to static libraries
        let backend = FfiBackend::new().unwrap();
        // Initialize the Barretenberg API
        let mut api = BarretenbergApi::new(backend);
        // Load up the aggregation circuit from disk
        let mut circuit = BarretenbergCircuit::new(&mut api, program_artifact_path);
        // Compute the proof from the witness bytes
        let prove_response = circuit.circuit_prove(&mut api, input_map).unwrap();
        let verify_response = circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
        assert!(verify_response.verified);
    }

    #[test]
    fn test_compliance_witness() {
        // Initialize the structured reference string
        init_srs();

        // Helper to generate the identical consumed resource entries from the TOML
        let create_consumed_resource = ConsumedResourceWitness {
            resource: Resource {
                logic_ref: [2; DIGEST_BYTES],
                label_ref: [3; DIGEST_BYTES],
                value_ref: [4; DIGEST_BYTES],
                quantity: 100,
                nonce: [5; DIGEST_BYTES],
                nk_commitment: [
                    206, 188, 136, 130, 254, 203, 236, 127, 184, 13, 44, 244, 179, 18, 190, 192,
                    24, 136, 76, 45, 102, 102, 124, 103, 169, 5, 8, 33, 75, 216, 186, 252,
                ],
                is_ephemeral: false,
                rand_seed: [6; DIGEST_BYTES],
            },
            cm_merkle_path: MerklePath {
                depth: 0,
                path: [(FieldElement::from(0u128), false); MAX_TREE_DEPTH],
            },
            nf_key: NullifierKey {
                bytes: [1; DIGEST_BYTES],
            },
        };

        // Helper to generate the identical created resource entries from the TOML
        let create_created_resource = Resource {
            logic_ref: [2; DIGEST_BYTES],
            label_ref: [3; DIGEST_BYTES],
            value_ref: [4; DIGEST_BYTES],
            quantity: 100,
            nonce: [
                252, 148, 204, 243, 140, 31, 54, 179, 170, 17, 251, 240, 6, 82, 245, 232,
                123, 157, 28, 182, 32, 87, 2, 87, 35, 189, 171, 90, 51, 95, 107, 183,
            ],
            nk_commitment: [
                206, 188, 136, 130, 254, 203, 236, 127, 184, 13, 44, 244, 179, 18, 190, 192,
                24, 136, 76, 45, 102, 102, 124, 103, 169, 5, 8, 33, 75, 216, 186, 252,
            ],
            is_ephemeral: false,
            rand_seed: [7; DIGEST_BYTES],
        };

        // Construct the literal ComplianceWitness object
        let compliance_witness = ComplianceWitness {
            consumed_count: 1,
            created_count: 1,
            ephemeral_root: [0; DIGEST_BYTES],
            rcv: EmbeddedCurveScalar {
                lo: FieldElement::from(1u128), // "0x01"
                hi: FieldElement::from(0u128), // "0x00"
            },
            consumed_data: [
                create_consumed_resource,
                create_consumed_resource,
                create_consumed_resource,
                create_consumed_resource,
            ],
            created_resources: [
                create_created_resource,
                create_created_resource,
                create_created_resource,
                create_created_resource,
            ],
        };
        // Construct inputs for proving
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), compliance_witness.into());
        // Load up the aggregation circuit from disk
        let program_artifact_path = PathBuf::from(COMPLIANCE_CIRCUIT_PATH);
        // Use the FFI backend which links directly to static libraries
        let backend = FfiBackend::new().unwrap();
        // Initialize the Barretenberg API
        let mut api = BarretenbergApi::new(backend);
        // Load up the aggregation circuit from disk
        let mut circuit = BarretenbergCircuit::new(&mut api, program_artifact_path);
        // Compute the proof from the witness bytes
        let prove_response = circuit.circuit_prove(&mut api, input_map).unwrap();
        let verify_response = circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
        assert!(verify_response.verified);
    }

    #[test]
    fn test_delta_verify_witness() {
        // Initialize the structured reference string
        init_srs();
        let public_key = EmbeddedCurvePoint {
            x: FieldElement::try_from_str("0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f").unwrap(),
            y: FieldElement::try_from_str("0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c").unwrap(),
        };
        let sig_s = EmbeddedCurveScalar {
            lo: FieldElement::try_from_str("0x5fd1ac0ad411110674830c54cb506212").unwrap(),
            hi: FieldElement::try_from_str("0x281906862cdb4e0efec7226d757fe803").unwrap(),
        };
        let sig_e = EmbeddedCurveScalar {
            lo: FieldElement::try_from_str("0x6c368959f958e525d761d06c47fd2ad6").unwrap(),
            hi: FieldElement::try_from_str("0x013f6a902c6c0efafdadbd4de409690d").unwrap(),
        };
        let message = FieldElement::try_from_str("0x2bc").unwrap();
        // Construct inputs for proving
        let mut input_map = InputMap::new();
        input_map.insert("public_key".to_string(), public_key.into());
        input_map.insert("message".to_string(), InputValue::Field(message));
        input_map.insert("signature".to_string(), InputValue::Vec(vec![sig_s.into(), sig_e.into()]));
        // Load up the aggregation circuit from disk
        let program_artifact_path = PathBuf::from(DELTA_VERIFY_CIRCUIT_PATH);
        // Use the FFI backend which links directly to static libraries
        let backend = FfiBackend::new().unwrap();
        // Initialize the Barretenberg API
        let mut api = BarretenbergApi::new(backend);
        // Load up the aggregation circuit from disk
        let mut circuit = BarretenbergCircuit::new(&mut api, program_artifact_path);
        // Compute the proof from the witness bytes
        let prove_response = circuit.circuit_prove(&mut api, input_map).unwrap();
        let verify_response = circuit.circuit_verify(&mut api, prove_response.clone()).unwrap();
        assert!(verify_response.verified);
    }
}
