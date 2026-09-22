use noirc_abi::InputMap;
use noirc_abi::input_parser::InputValue;
use acir::FieldElement;
use serde::{Deserialize, Serialize};
use nodes::write_bytes;
use rand::Rng;
use ark_bn254::Fq;
use ark_ff::UniformRand;
use ark_ff::PrimeField;
use alloy::primitives::keccak256;
use sha2::{Sha256, Digest};
use borsh::{BorshSerialize, BorshDeserialize};
use acir::AcirField;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::Backend;
use ark_ec::AffineRepr;
use std::ops::Neg;
use ark_ff::BigInteger;
use std::ops::Mul;
use ark_ec::CurveGroup;
use k256::AffinePoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nodes::read_bytes;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use std::io::Write;
use std::io::Read;

/// Path to file containing the aggregation circuit
pub const TRANSFER_AUTH_CIRCUIT_PATH: &str = "../circuits/target/transfer_auth.json";
// You may need to define this constant at the top of your file alongside TRANSFER_AUTH_CIRCUIT_PATH
pub const COMPLIANCE_CIRCUIT_PATH: &str = "../circuits/target/compliance.json";
// You may need to define this constant at the top of your file alongside DELTA_VERIFY_CIRCUIT_PATH
const DELTA_VERIFY_CIRCUIT_PATH: &str = "../circuits/target/delta_verify.json";

pub const DIGEST_BYTES: usize = 32;
// Constants for bounding unbounded loops and variable-length arrays
const MAX_FORWARDER_ADDR_LEN: usize = 20;
const MAX_ERC20_TOKEN_ADDR_LEN: usize = 20;
pub const MAX_ETH_ADDR_LEN: usize = 20;
const MAX_AUTH_PK_LEN: usize = 65;
pub const DISCOVERY_PK_LEN: usize = 65;
pub const DISCOVERY_SHARED_POINT_LEN: usize = 32;
const DISCOVERY_CIPHERTEXT_LEN: usize = 16;
const MAX_ENCRYPTION_PK_LEN: usize = 65;
const MAX_AUTH_SIG_LEN: usize = 64;
const MAX_RESOURCE_CIPHERTEXT_LEN: usize = 340;
const MAX_DISCOVERY_CIPHERTEXT_LEN: usize = 340;
const MAX_PERMIT_NONCE_LEN: usize = 32;
const MAX_PERMIT_DEADLINE_LEN: usize = 32;
const MAX_PERMIT_SIG_LEN: usize = 65;
const MAX_INPUT_LEN: usize = 256;
const MAX_OUTPUT_LEN: usize = 64;
const MAX_FORWARDER_CALLDATA_LEN: usize = 340;
const MAX_BLOBS_PER_PAYLOAD: usize = 1;
const MAX_BLOB_LEN: usize = 340;
const MAX_LOGIC_DIGEST_BUF_LEN: usize = 1461;
pub const CALL_TYPE_WRAP: u8 = 0;
pub const CALL_TYPE_UNWRAP: u8 = 1;
const PRF_EXPAND_PERSONALIZATION_LEN: usize = 16;
pub const MAX_CREATED: usize = 4;
pub const MAX_CONSUMED: usize = 4;
const MAX_KINDS: u32 = 8;
pub const MAX_TREE_DEPTH: usize = 32; // Set this to your actual max commitment tree depth
const CONSUMED_COUNT_BYTES: usize = 4;
const CREATED_COUNT_BYTES: usize = 4;
const BASE_FIELD_BYTES: usize = 32;
const QUANTITY_BYTES: usize = 16;
const RESOURCE_BYTES: usize = 6*DIGEST_BYTES + QUANTITY_BYTES + 1;
const RCM_BYTES: usize = PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES;
const PRF_EXPAND_RCM: u8 = 1;
const PRF_EXPAND_PERSONALIZATION: [u8; PRF_EXPAND_PERSONALIZATION_LEN] = *b"RISC0_ExpandSeed";
const PSI_BYTES: usize = PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES;
const PRF_EXPAND_PSI: u8 = 0;
const NONCE_DERIVATION_PERSONALIZATION_LEN: usize = 20;
const NONCE_DERIVATION_PERSONALIZATION: [u8; NONCE_DERIVATION_PERSONALIZATION_LEN] = *b"ARM_NONCE_DERIVATION";
const NONCE_INDEX_BYTES: usize = 4;
const NONCE_PREIMAGE_LEN: usize = NONCE_DERIVATION_PERSONALIZATION_LEN + NONCE_INDEX_BYTES + DIGEST_BYTES;
const PAYLOAD_LEN_BYTES: usize = 4;
const BLOB_LEN_BYTES: u32 = 4;
const MAX_COMPLIANCE_DIGEST_BUF_LEN: usize = 3*DIGEST_BYTES*MAX_CONSUMED + 2*DIGEST_BYTES*MAX_CREATED + CONSUMED_COUNT_BYTES + CREATED_COUNT_BYTES + 2*BASE_FIELD_BYTES;
pub const ENCRYPTION_NONCE_LEN: usize = 12;
pub const DISCOVERY_NONCE_LEN: usize = 12;
const RESOURCE_WITH_LABEL_BYTES: usize = RESOURCE_BYTES + MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN;

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

pub type Nullifier = [u8; DIGEST_BYTES];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ciphertext {
    // AES GCM encrypted message
    pub cipher: [u8; DISCOVERY_CIPHERTEXT_LEN],
    // 96-bits; unique per message
    pub nonce: [u8; DISCOVERY_NONCE_LEN],
    // Sender's public key
    pub pk: AffinePoint,
}

impl Ciphertext {
    /// Serializes the Ciphertext into a fixed-length byte array of size `N`.
    /// The layout is: Nonce (12 bytes) | PK (65 bytes) | Cipher Data | Zero Padding
    pub fn to_bytes(&self) -> [u8; DISCOVERY_CIPHERTEXT_LEN + DISCOVERY_NONCE_LEN + DISCOVERY_PK_LEN] {
        let mut bytes = [0u8; _];
        let mut offset: usize = 0;
        // 1. Write nonce (12 bytes)
        write_bytes(&mut bytes, &mut offset, &self.nonce);
        // 2. Write public key (65 bytes, uncompressed SEC1)
        let pk_bytes = self.pk.to_encoded_point(false);
        write_bytes(&mut bytes, &mut offset, pk_bytes.as_bytes());
        // 3. Write cipher data (remaining bytes are implicitly zero-padded)
        write_bytes(&mut bytes, &mut offset, &self.cipher);
        bytes
    }

    /// Deserializes a Ciphertext from a fixed-length byte array of size `N`.
    pub fn from_bytes(bytes: &[u8; DISCOVERY_CIPHERTEXT_LEN + DISCOVERY_NONCE_LEN + DISCOVERY_PK_LEN]) -> Option<Self> {
        let mut offset: usize = 0;
        // 1. Read nonce
        let nonce = read_bytes(bytes, &mut offset);
        // 2. Read public key
        let pk_slice: [u8; DISCOVERY_PK_LEN] = read_bytes(bytes, &mut offset);
        let encoded_point = k256::EncodedPoint::from_bytes(&pk_slice).ok()?;
        let pk = Option::from(k256::AffinePoint::from_encoded_point(&encoded_point))?;
        // 3. Read cipher data
        let cipher = read_bytes(bytes, &mut offset);
        Some(Self {cipher, nonce, pk, })
    }
}

/// ARM Resource
#[derive(Deserialize, Serialize, Clone, Copy, Default, BorshSerialize, BorshDeserialize, Debug)]
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

impl Resource {
    /// Compute the inner psi for the resource
    pub fn psi(self) -> [u8; DIGEST_BYTES] {
        let mut bytes = [0u8; PSI_BYTES];
        let mut offset: usize = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        write_bytes(&mut bytes, &mut offset, &PRF_EXPAND_PERSONALIZATION);
        // Write the PRF_EXPAND_PSI
        write_bytes(&mut bytes, &mut offset, &[PRF_EXPAND_PSI]);
        // Write the random seed
        write_bytes(&mut bytes, &mut offset, &self.rand_seed);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, &self.nonce);
        assert_eq!(offset, PSI_BYTES, "resource psi pre-image malformed");
        keccak256(bytes).0
    }
    
    /// Compute the randomness to commit the resource
    pub fn rcm(self) -> [u8; DIGEST_BYTES]  {
        let mut bytes = [0u8; RCM_BYTES];
        let mut offset: usize = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        write_bytes(&mut bytes, &mut offset, &PRF_EXPAND_PERSONALIZATION);
        // Write the PRF_EXPAND_RCM
        write_bytes(&mut bytes, &mut offset, &[PRF_EXPAND_RCM]);
        // Write the random seed
        write_bytes(&mut bytes, &mut offset, &self.rand_seed);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, &self.nonce);
        assert_eq!(offset, RCM_BYTES, "resource rcm pre-image malformed");
        keccak256(bytes).0
    }
    
    fn to_bytes(self) -> [u8; RESOURCE_BYTES] {
        // Concatenate all the components of this resource
        let mut bytes = [0; RESOURCE_BYTES];
        let mut offset: usize = 0;
        // Write the image ID bytes
        write_bytes(&mut bytes, &mut offset, &self.logic_ref);
        // Write the label_ref bytes
        write_bytes(&mut bytes, &mut offset, &self.label_ref);
        // Write the fungible value_ref bytes
        write_bytes(&mut bytes, &mut offset, &self.value_ref);
        // Write the quantity bytes
        let q_bytes = self.quantity.to_be_bytes();
        write_bytes(&mut bytes, &mut offset, &q_bytes);
        // Write the nonce bytes
        write_bytes(&mut bytes, &mut offset, &self.nonce);
        // Write the nullifier public key bytes
        write_bytes(&mut bytes, &mut offset, &self.nk_commitment);
        // Write the randomness seed bytes
        let rcm = self.rcm();
        write_bytes(&mut bytes, &mut offset, &rcm);
        // Write the ephemeral flag
        write_bytes(&mut bytes, &mut offset, &[self.is_ephemeral as u8]);
        assert_eq!(offset, RESOURCE_BYTES, "resource commitment pre-image malformed");
        bytes
    }

    /// Compute the commitment to the resource
    pub fn commitment(self) -> [u8; DIGEST_BYTES] {
        // Now produce the hash
        keccak256(self.to_bytes()).0
    }

    /// Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: NullifierKey) -> [u8; DIGEST_BYTES] {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, cm)
    }

    /// Compute the nullifier of the resource from its commitment
    pub fn nullifier_from_commitment(self, nk: NullifierKey, cm: [u8; DIGEST_BYTES]) -> Nullifier {
        // Make sure that the nullifier public key corresponds to the secret key
        assert_eq!(self.nk_commitment, crate::wallet::NullifierKey(nk.bytes).commit().0);
        let mut bytes = [0u8; 4 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the resource commitment
        write_bytes(&mut bytes, &mut offset, &cm);
        // Write the nullifier secret key
        write_bytes(&mut bytes, &mut offset, &nk.bytes);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, &self.nonce);
        // Write psi
        let psi = self.psi();
        write_bytes(&mut bytes, &mut offset, &psi);
        assert_eq!(offset, 4 * DIGEST_BYTES, "nullifier pre-image malformed");
        keccak256(bytes).0
    }

    /// Derives the nonce by hashing
    /// `ARM_NONCE_DERIVATION || index_be || nullifiers_digest`.
    pub fn derive_nonce(index: u32, nullifiers_digest: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        let mut bytes = [0u8; NONCE_PREIMAGE_LEN];
        let mut offset: usize = 0;
        write_bytes(&mut bytes, &mut offset, &NONCE_DERIVATION_PERSONALIZATION);
        write_bytes(&mut bytes, &mut offset, &index.to_be_bytes());
        write_bytes(&mut bytes, &mut offset, &nullifiers_digest);
        assert_eq!(offset, NONCE_PREIMAGE_LEN, "nonce pre-image malformed");
        Sha256::digest(&bytes[..]).into()
    }

    /// Hashes the concatenation of the passed nullifier digests.
    /// Fails if `nullifiers` is empty.
    pub fn hash_nullifiers(nullifiers: [Nullifier; MAX_CONSUMED], count: usize) -> [u8; DIGEST_BYTES] {
        assert!(count > 0);
        assert!(count <= MAX_CONSUMED);
        let mut hash_input = [0u8; MAX_CONSUMED * DIGEST_BYTES];
        let mut offset: usize = 0;
        for i in 0..MAX_CONSUMED {
            if i < count {
                write_bytes(&mut hash_input, &mut offset, &nullifiers[i]);
            }
        }
        assert_eq!(offset, count * DIGEST_BYTES, "nullifier concatenation malformed");
        Sha256::digest(&hash_input[..offset]).into()
    }

    /// Compute the kind of the resource
    pub fn kind<B: Backend>(&self, api: &mut BarretenbergApi<B>) -> EmbeddedCurvePoint {
        // Concatenate the logic_ref and label_ref
        let logic_ref = FieldElement::from_le_bytes_reduce(&self.logic_ref);
        let label_ref = FieldElement::from_le_bytes_reduce(&self.label_ref);
        // Hash to a curve point
        let point = api.pedersen_commit(vec![
            logic_ref.to_be_bytes().to_vec(),
            label_ref.to_be_bytes().to_vec(),
        ], 0).expect("unable to compute Pedersen commitment").point;
        // Convert back to the EmbeddedCurvePoint type
        EmbeddedCurvePoint {
            x: FieldElement::from_be_bytes_reduce(&point.x),
            y: FieldElement::from_be_bytes_reduce(&point.y),
        }
    }
}

/// The struct encoded in the resource payload for persistent created resources.
pub struct ResourceWithLabel {
    pub resource: Resource,
    /// Address of the forwarder contract for this resource.
    pub forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    /// Address of the wrapped token within this resource (e.g. USDC).
    pub erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
}

impl ResourceWithLabel {
    pub fn to_bytes(self) -> [u8; RESOURCE_WITH_LABEL_BYTES] {
        // Concatenate all the components of this resource
        let mut bytes = [0; RESOURCE_WITH_LABEL_BYTES];
        let mut offset: usize = 0;
        // Write the resource bytes
        write_bytes(&mut bytes, &mut offset, &self.resource.to_bytes());
        // Write the forwarder address bytes
        write_bytes(&mut bytes, &mut offset, &self.forwarder_addr);
        // Write the token address bytes
        write_bytes(&mut bytes, &mut offset, &self.erc20_token_addr);
        assert_eq!(offset, RESOURCE_WITH_LABEL_BYTES, "resource with label bytes malformed");
        bytes
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
    pub auth_pk: [u8; MAX_AUTH_PK_LEN],
    /// Public key. Obtain from the receiver for persistent resource_ciphertext
    pub encryption_pk: EmbeddedCurvePoint,
}

impl Default for ValueInfo {
    fn default() -> Self {
        Self {
            auth_pk: [0; _],
            encryption_pk: EmbeddedCurvePoint::point_at_infinity(),
        }
    }
}

impl From<ValueInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: ValueInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("auth_pk".to_string(), Array(res.auth_pk).into());
        map.insert("encryption_pk".to_string(), res.encryption_pk.into());
        InputValue::Struct(map)
    }
}

/// LabelInfo holds information about label plaintext.
#[derive(Default, Copy, Clone)]
pub struct LabelInfo {
    /// Address of the forwarder contract for this resource.
    pub forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    /// Address of the wrapped token within this resource (e.g. USDC).
    pub erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
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
#[derive(Copy, Clone)]
pub struct PermitInfo {
    /// Nonce of the permit2 signature.
    pub permit_nonce: [u8; MAX_PERMIT_NONCE_LEN],
    /// Deadline of the permit2 signature (i.e., when does it expire)
    pub permit_deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    /// Signature
    pub permit_sig: [u8; MAX_PERMIT_SIG_LEN],
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
#[derive(Default, Copy, Clone)]
pub struct ForwarderInfo {
    /// Wrapping/Unwrapping of a resource (i.e., mint/burn).
    pub call_type: u8,
    /// Address of the ethereum account
    pub ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    /// PermitInfo (see struct)
    pub permit: Option<PermitInfo>,
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
pub struct TransferAuthWitness {
    /// Resource this witness is about.
    pub resource: Resource,
    /// Is this a consumed or created resource.
    pub is_consumed: bool,
    /// Action tree root
    pub action_root: [u8; DIGEST_BYTES],
    /// Nullifier key for the resource.
    pub nullifier_key: Option<NullifierKey>,
    /// See ValueInfo struct.
    pub value_info: Option<ValueInfo>,
    /// A consumed persistent resource requires an authorization signature
    pub auth_sig: Option<[u8; MAX_AUTH_SIG_LEN]>,
    /// See EncryptionInfo struct.
    pub encryption_info: Option<EncryptionInfo>,
    /// See LabelInfo struct.
    pub label_info: Option<LabelInfo>,
    /// See ForwarderInfo struct.
    pub forwarder_info: Option<ForwarderInfo>,
}

impl From<TransferAuthWitness> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: TransferAuthWitness) -> Self {
        let mut map = InputMap::new();
        map.insert("resource".to_string(), res.resource.into());
        map.insert("is_consumed".to_string(), InputValue::Field(FieldElement::from(res.is_consumed)));
        map.insert("action_root".to_string(), Array(res.action_root).into());
        map.insert("auth_sig".to_string(), option_to_input_value(res.auth_sig.map(Array)));
        map.insert("nullifier_key".to_string(), option_to_input_value(res.nullifier_key));
        map.insert("value_info".to_string(), option_to_input_value(res.value_info));
        map.insert("encryption_info".to_string(), option_to_input_value(res.encryption_info));
        map.insert("label_info".to_string(), option_to_input_value(res.label_info));
        map.insert("forwarder_info".to_string(), option_to_input_value(res.forwarder_info));
        InputValue::Struct(map)
    }
}

/// The EncryptionInfo struct holds information about the encryption keys for the
/// recipient/sender of a resource in a transaction.
pub struct EncryptionInfo {
    /// Secret key. randomly generated for persistent resource_ciphertext
    pub sender_sk: EmbeddedCurveScalar,
    /// randomly generated for persistent resource_ciphertext(12 bytes)
    pub encryption_nonce: [u8; ENCRYPTION_NONCE_LEN],
    /// The discovery ciphertext for the resource
    pub discovery_ciphertext: [u8; MAX_DISCOVERY_CIPHERTEXT_LEN],
    pub discovery_ciphertext_len: u32,
}

impl Default for EncryptionInfo {
    fn default() -> Self {
        Self {
            sender_sk: EmbeddedCurveScalar::zero(),
            encryption_nonce: [0; _],
            discovery_ciphertext: [0; _],
            discovery_ciphertext_len: 0,
        }
    }
}

impl From<EncryptionInfo> for InputValue {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(res: EncryptionInfo) -> Self {
        let mut map = InputMap::new();
        map.insert("sender_sk".to_string(), res.sender_sk.into());
        map.insert("encryption_nonce".to_string(), Array(res.encryption_nonce).into());
        map.insert("discovery_ciphertext_len".to_string(), InputValue::Field(FieldElement::from(res.discovery_ciphertext_len)));
        map.insert("discovery_ciphertext".to_string(), Array(res.discovery_ciphertext).into());
        InputValue::Struct(map)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Copy, Default)]
pub struct MerklePath {
    pub path: [(FieldElement, bool); MAX_TREE_DEPTH],
    pub depth: usize, // Logical length of the path (since the array is statically sized)
}

impl MerklePath {
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root<B: Backend>(&self, api: &mut BarretenbergApi<B>, leaf: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        let current_root = FieldElement::from_le_bytes_reduce(&leaf);
        let mut current_root = current_root.to_be_bytes();
        for i in 0..MAX_TREE_DEPTH {
            if i < self.depth {
                let (sibling, leaf_is_on_right) = self.path[i];
                current_root = if leaf_is_on_right {
                    api.poseidon2_hash(vec![sibling.to_be_bytes(), current_root])
                } else {
                    api.poseidon2_hash(vec![current_root, sibling.to_be_bytes()])
                }.expect("unable to compute Poseidon hash").hash;
            }
        }
        let mut current_root_bytes = [0u8; DIGEST_BYTES];
        current_root_bytes.copy_from_slice(&current_root);
        current_root_bytes.reverse();
        current_root_bytes
    }

    /// Returns the logical length of the Merkle path.
    pub fn len(&self) -> usize {
        self.depth
    }

    /// Checks if the Merkle path is empty.
    pub fn is_empty(&self) -> bool {
        self.depth == 0
    }

    /// Creates an empty Merkle path.
    pub fn empty() -> Self {
        MerklePath {
            path: [(FieldElement::zero(), false); MAX_TREE_DEPTH],
            depth: 0,
        }
    }
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
#[derive(Clone, Copy, Default)]
pub struct ConsumedResourceWitness {
    /// The consumed resource.
    pub resource: Resource,
    /// The path from the consumed commitment to the root of the commitment tree.
    pub cm_merkle_path: MerklePath,
    /// Nullifier key of the consumed resource.
    pub nf_key: NullifierKey,
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
#[derive(Clone, Copy, Default, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ConsumedResourcePublic {
    /// The nullifier of the consumed [Resource].
    pub resource_nullifier: [u8; DIGEST_BYTES],
    /// The logic reference of the consumed [Resource].
    pub resource_logic_ref: [u8; DIGEST_BYTES],
    /// The root of the Merkle tree where the resource commitment is in.
    pub commitment_tree_root: [u8; DIGEST_BYTES],
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
#[derive(Clone, Copy, Default, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, BorshSerialize, BorshDeserialize)]
pub struct CreatedResourcePublic {
    /// The commitment to the created [Resource].
    pub resource_commitment: [u8; DIGEST_BYTES],
    /// The logic reference of the created [Resource].
    pub resource_logic_ref: [u8; DIGEST_BYTES],
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
#[derive(Eq, Hash, PartialEq, Ord, PartialOrd, Debug, Copy, Clone)]
pub struct EmbeddedCurvePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl EmbeddedCurvePoint {
    /// True if this point is the point at infinity
    pub fn is_infinite(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }

    /// Returns the curve's generator point.
    pub fn generator() -> Self {
        // Generator point for the grumpkin curve (y^2 = x^3 - 17)
        let generator = ark_grumpkin::Affine::generator();
        let generator_x = FieldElement::from_repr(generator.x().unwrap());
        let generator_y = FieldElement::from_repr(generator.y().unwrap());
        Self { x: generator_x, y: generator_y }
    }

    /// Returns the null element of the curve; 'the point at infinity'
    pub fn point_at_infinity() -> Self {
        EmbeddedCurvePoint { x: FieldElement::zero(), y: FieldElement::zero() }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut combined_bytes = [0u8; 64];
        combined_bytes[..32].copy_from_slice(&self.x.to_le_bytes());
        combined_bytes[32..].copy_from_slice(&self.y.to_le_bytes());
        combined_bytes
    }

    pub fn from_bytes(bigint: &[u8; 64]) -> Self {
        Self {
            x: FieldElement::from_le_bytes_reduce(&bigint[..32]),
            y: FieldElement::from_le_bytes_reduce(&bigint[32..]),
        }
    }
}

impl BorshSerialize for EmbeddedCurvePoint {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for EmbeddedCurvePoint {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self::from_bytes(&<[u8; _]>::deserialize_reader(reader)?))
    }
}

impl Neg for EmbeddedCurvePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self { x: self.x, y: -self.y }
    }
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

impl From<EmbeddedCurvePoint> for ark_grumpkin::Affine {
    fn from(point: EmbeddedCurvePoint) -> Self {
        ark_grumpkin::Affine::new(point.x.into_repr(), point.y.into_repr())
    }
}

impl From<ark_grumpkin::Affine> for EmbeddedCurvePoint {
    fn from(point: ark_grumpkin::Affine) -> Self {
        Self { x: FieldElement::from_repr(point.x), y: FieldElement::from_repr(point.y) }
    }
}

impl Mul<EmbeddedCurveScalar> for EmbeddedCurvePoint {
    type Output = Self;

    fn mul(self, scalar: EmbeddedCurveScalar) -> Self::Output {
        // 1. Convert the point to ark_grumpkin::Affine
        let affine_point: ark_grumpkin::Affine = self.into();
        
        // 2. Convert the scalar to ark_grumpkin::Fr
        let fr_scalar: ark_grumpkin::Fr = scalar.into();
        
        // 3. Perform the scalar multiplication (returns a Projective point)
        let projective_result = affine_point * fr_scalar;
        
        // 4. Convert back to Affine, and then to our custom EmbeddedCurvePoint
        projective_result.into_affine().into()
    }
}

/// The compliance instance contains all public inputs to the compliance proof.
#[derive(Eq, Hash, PartialEq, Ord, PartialOrd, Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ComplianceInstance {
    /// Public information of consumed resources
    pub consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    pub consumed_count: u32,
    /// Public information of created resources
    pub created_publics: [CreatedResourcePublic; MAX_CREATED],
    pub created_count: u32,
    /// The delta coordinates of the created resource
    pub delta: EmbeddedCurvePoint,
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

impl ComplianceInstance {
    pub fn digest(&self) -> FieldElement {
        let mut buf = [0; MAX_COMPLIANCE_DIGEST_BUF_LEN];
        let mut buf_len = 0;
        let consumed_count_bytes = u32::from(self.consumed_count).to_le_bytes();
        write_bytes(&mut buf, &mut buf_len, &consumed_count_bytes);
        for consumed_public in self.consumed_publics {
            write_bytes(&mut buf, &mut buf_len, &consumed_public.resource_nullifier);
            write_bytes(&mut buf, &mut buf_len, &consumed_public.resource_logic_ref);
            write_bytes(&mut buf, &mut buf_len, &consumed_public.commitment_tree_root);
        }

        let created_count_bytes = u32::from(self.created_count).to_le_bytes();
        write_bytes(&mut buf, &mut buf_len, &created_count_bytes);
        for created_public in self.created_publics {
            write_bytes(&mut buf, &mut buf_len, &created_public.resource_commitment);
            write_bytes(&mut buf, &mut buf_len, &created_public.resource_logic_ref);
        }

        assert!(!self.delta.is_infinite());
        write_bytes(&mut buf, &mut buf_len, &self.delta.x.to_le_bytes());
        write_bytes(&mut buf, &mut buf_len, &self.delta.y.to_le_bytes());
        
        assert_eq!(buf_len, MAX_COMPLIANCE_DIGEST_BUF_LEN, "compliance instance digest pre-image malformed");
        FieldElement::from_le_bytes_reduce(keccak256(buf).as_slice())
    }
}

/// Scalar for the embedded curve represented as low and high limbs
/// By definition, the scalar field of the embedded curve is base field of the proving system curve.
/// It may not fit into a Field element, so it is represented with two Field elements; its low and high limbs.
#[derive(Clone, Copy, Debug)]
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

impl From<EmbeddedCurveScalar> for ark_grumpkin::Fr {
    fn from(scalar: EmbeddedCurveScalar) -> Self {
        // Combine the first 16 bytes (128 bits) of each limb into a single 32-byte array
        let combined_bytes = scalar.to_bytes();
        // Construct the Grumpkin scalar from the combined bytes
        ark_grumpkin::Fr::from_le_bytes_mod_order(&combined_bytes)
    }
}

impl From<ark_grumpkin::Fr> for EmbeddedCurveScalar {
    fn from(scalar: ark_grumpkin::Fr) -> Self {
        // Convert the Grumpkin scalar to its byte representation
        let bigint = scalar.into_bigint().to_bytes_le();
        // Then convert the byte representation to this type
        Self::from_bytes(&bigint)
    }
}

impl EmbeddedCurveScalar {
    /// Generate a nullifier key
    pub fn random(rng: &mut impl Rng) -> Self {
        // Generate the random field element
        let random_fq = Fq::rand(rng);
        let random_bigint = random_fq.into_bigint();
        // hi: Shift right by 128 to get the top 128 bits
        let hi = random_bigint >> 128;
        // lo: Shift left by 128, then right by 128 to mask out the top 128 bits
        let lo = (random_bigint << 128) >> 128;
        EmbeddedCurveScalar {
            hi: FieldElement::from_repr(hi.into()),
            lo: FieldElement::from_repr(lo.into()),
        }
    }
    /// Zero scalar
    pub fn zero() -> Self {
        Self { lo: FieldElement::zero(), hi: FieldElement::zero() }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        // Combine the first 16 bytes (128 bits) of each limb into a single 32-byte array
        let mut combined_bytes = [0u8; 32];
        combined_bytes[..16].copy_from_slice(&self.lo.to_le_bytes()[..16]);
        combined_bytes[16..].copy_from_slice(&self.hi.to_le_bytes()[..16]);
        combined_bytes
    }

    pub fn from_bytes(bigint: &[u8]) -> Self {
        Self {
            lo: FieldElement::from_le_bytes_reduce(&bigint[..16]),
            hi: FieldElement::from_le_bytes_reduce(&bigint[16..]),
        }
    }
}

/// The compliance witness contains all private inputs to the compliance proof.
pub struct ComplianceWitness {
    /// Private information of consumed resources
    pub consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    pub consumed_count: u32,
    /// Private information of created resources
    pub created_resources: [Resource; MAX_CREATED],
    pub created_count: u32,
    /// The existing root for ephemeral resources
    pub ephemeral_root: [u8; DIGEST_BYTES],
    /// Bytes of randomness for the delta commitment `rcv`
    pub rcv: EmbeddedCurveScalar, // Scalar parsed to field
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

/// An expirable blob consists of a blob and a deletion criterion.
#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    pub blob: [u8; MAX_BLOB_LEN],
    pub blob_len: u32,
    /// The deletion criterion for the blob.
    pub deletion_criterion: bool,
}

/// Application data contains four different types of payloads.
#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct AppData {
    /// The resource payload blobs.
    pub resource_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    pub resource_payload_len: u32,
    /// The application payload blobs.
    pub application_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    pub application_payload_len: u32,
    /// The external payload blobs.
    pub external_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    pub external_payload_len: u32,
    /// The discovery payload blobs.
    pub discovery_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    pub discovery_payload_len: u32,
}

impl Default for AppData {
    /// Creates a new, empty AppData.
    fn default() -> Self {
        let payload = [ExpirableBlob {
            blob: [0; MAX_BLOB_LEN],
            blob_len: 0,
            deletion_criterion: false,
        }; MAX_BLOBS_PER_PAYLOAD];
        AppData {
            resource_payload: payload,
            resource_payload_len: 0,
            application_payload: payload,
            application_payload_len: 0,
            external_payload: payload,
            external_payload_len: 0,
            discovery_payload: payload,
            discovery_payload_len: 0,
        }
    }
}

/// Represents a logic instance with its associated data.
#[derive(Copy, Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ResourceLogicInstance {
    /// The logic instance's tag (either commitment or nullifier)
    pub tag: [u8; DIGEST_BYTES],
    /// The root digest of the logic instance.
    pub action_root: [u8; DIGEST_BYTES],
    /// Indicates whether the logic instance is for a consumed resource.
    pub is_consumed: bool,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
}

impl ResourceLogicInstance {
    pub fn digest(self) -> FieldElement {
        let mut buf = [0; MAX_LOGIC_DIGEST_BUF_LEN];
        let mut buf_len = 0;
        write_bytes(&mut buf, &mut buf_len, &self.tag);
        write_bytes(&mut buf, &mut buf_len, &self.action_root);
        write_bytes(&mut buf, &mut buf_len, &[self.is_consumed as u8]);

        let lists = [
            (self.app_data.resource_payload, self.app_data.resource_payload_len),
            (self.app_data.application_payload, self.app_data.application_payload_len),
            (self.app_data.external_payload, self.app_data.external_payload_len),
            (self.app_data.discovery_payload, self.app_data.discovery_payload_len),
        ];

        for list_idx in 0..4 {
            let list = lists[list_idx].0;
            let list_len = lists[list_idx].1;
            
            let len_bytes = u32::from(list_len).to_le_bytes();
            write_bytes(&mut buf, &mut buf_len, &len_bytes);

            for p_idx in 0..MAX_BLOBS_PER_PAYLOAD {
                let p = list[p_idx];
                let p_len_bytes = u32::from(p.blob_len).to_le_bytes();
                write_bytes(&mut buf, &mut buf_len, &p_len_bytes);
                write_bytes(&mut buf, &mut buf_len, &p.blob);
                write_bytes(&mut buf, &mut buf_len, &[p.deletion_criterion as u8]);
            }
        }
        assert_eq!(buf_len, MAX_LOGIC_DIGEST_BUF_LEN, "logic instance digest pre-image malformed");
        FieldElement::from_le_bytes_reduce(keccak256(buf).as_slice())
    }
}

pub fn encode_wrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    quantity: u128,
    nonce: [u8; MAX_PERMIT_NONCE_LEN],
    deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    action_tree_root: [u8; 32],
    signature: [u8; MAX_PERMIT_SIG_LEN],
) -> ([u8; MAX_INPUT_LEN], usize) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: usize = 0;
    write_bytes(&mut res, &mut offset, &[CALL_TYPE_WRAP]);
    write_bytes(&mut res, &mut offset, &erc20_token_addr);
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = u128::from(quantity).to_be_bytes();
    write_bytes(&mut res, &mut offset, &quantity_bytes);
    write_bytes(&mut res, &mut offset, &nonce);
    write_bytes(&mut res, &mut offset, &deadline);
    write_bytes(&mut res, &mut offset, &ethereum_account_addr);
    write_bytes(&mut res, &mut offset, &action_tree_root);
    write_bytes(&mut res, &mut offset, &signature);
    (res, offset)
}

pub fn encode_unwrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    quantity: u128,
) -> ([u8; MAX_INPUT_LEN], usize) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: usize = 0;
    write_bytes(&mut res, &mut offset, &[CALL_TYPE_UNWRAP]);
    write_bytes(&mut res, &mut offset, &erc20_token_addr);
    write_bytes(&mut res, &mut offset, &ethereum_account_addr);
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = u128::from(quantity).to_be_bytes();
    write_bytes(&mut res, &mut offset, &quantity_bytes);
    (res, offset)
}

pub fn encode_forwarder_calldata(
    forwarder: [u8; MAX_FORWARDER_ADDR_LEN],
    input: [u8; MAX_INPUT_LEN],
    output: [u8; MAX_OUTPUT_LEN],
) -> ([u8; MAX_FORWARDER_CALLDATA_LEN], usize) {
    let mut res = [0; MAX_FORWARDER_CALLDATA_LEN];
    let mut offset: usize = 0;
    write_bytes(&mut res, &mut offset, &forwarder);
    write_bytes(&mut res, &mut offset, &input);
    write_bytes(&mut res, &mut offset, &output);
    (res, offset)
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
