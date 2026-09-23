use std::option::Option;
use std::static_assert;
use core::{write_bytes, NullifierKey, Resource};
use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurveScalar, EmbeddedCurvePoint};
use std::aes128::aes128_encrypt;

// Constants for bounding unbounded loops and variable-length arrays
global MAX_FORWARDER_ADDR_LEN: u32 = 20;
global MAX_ERC20_TOKEN_ADDR_LEN: u32 = 20;
global MAX_ETH_ADDR_LEN: u32 = 20;
global MAX_AUTH_PK_LEN: u32 = 65;
global MAX_ENCRYPTION_PK_LEN: u32 = 65;
global MAX_AUTH_SIG_LEN: u32 = 64;
global MAX_RESOURCE_CIPHERTEXT_LEN: u32 = 340;
global MAX_DISCOVERY_CIPHERTEXT_LEN: u32 = 340;
global MAX_PERMIT_NONCE_LEN: u32 = 32;
global MAX_PERMIT_DEADLINE_LEN: u32 = 32;
global MAX_PERMIT_SIG_LEN: u32 = 65;
global MAX_INPUT_LEN: u32 = 256;
global MAX_OUTPUT_LEN: u32 = 64;
global MAX_FORWARDER_CALLDATA_LEN: u32 = 340;
global MAX_BLOBS_PER_PAYLOAD: u32 = 1;
global MAX_BLOB_LEN: u32 = 340;
global MAX_LOGIC_DIGEST_BUF_LEN: u32 = 1461;
global CALL_TYPE_WRAP: u8 = 0;
global CALL_TYPE_UNWRAP: u8 = 1;
global PRF_EXPAND_PERSONALIZATION_LEN: u32 = 16;
global PRF_EXPAND_PERSONALIZATION: [u8; PRF_EXPAND_PERSONALIZATION_LEN] = "RISC0_ExpandSeed".as_bytes();
global DIGEST_BYTES: u32 = 32;
global QUANTITY_BYTES: u32 = 16;
global RESOURCE_BYTES: u32 = 6*DIGEST_BYTES + QUANTITY_BYTES + 1;
global PSI_BYTES: u32 = PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES;
global RCM_BYTES: u32 = PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES;
global PRF_EXPAND_PSI: u8 = 0;
global PRF_EXPAND_RCM: u8 = 1;
global BLOB_LEN_BYTES: u32 = 4;
global PAYLOAD_LEN_BYTES: u32 = 4;
global ENCRYPTION_NONCE_LEN: u32 = 12;
global EMBEDDED_CURVE_BASE_FIELD_BYTES: u32 = 32;
global RESOURCE_WITH_LABEL_BYTES: u32 = RESOURCE_BYTES + MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN;

/// LabelInfo holds information about label plaintext.
struct LabelInfo {
    /// Address of the forwarder contract for this resource.
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    /// Address of the wrapped token within this resource (e.g. USDC).
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
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

/// ForwarderInfo holds information about the forwarder contract being used by a transaction.
struct ForwarderInfo {
    /// Wrapping/Unwrapping of a resource (i.e., mint/burn).
    call_type: u8,
    /// Address of the ethereum account
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    /// PermitInfo (see struct)
    permit: Option<PermitInfo>,
}

/// The TokenTransferWitness holds all the information necessary to generate a proof of the
/// resource logic of a given resource.
struct TransferAuthWitness {
    /// Resource this witness is about.
    resource: Resource,
    /// Is this a consumed or created resource.
    is_consumed: bool,
    /// Action tree root
    action_root: [u8; 32],
    /// Nullifier key for the resource.
    nullifier_key: Option<NullifierKey>,
    /// See ValueInfo struct.
    value_info: Option<ValueInfo>,
    /// A consumed persistent resource requires an authorization signature
    auth_sig: Option<[u8; MAX_AUTH_SIG_LEN]>,
    /// See EncryptionInfo struct.
    encryption_info: Option<EncryptionInfo>,
    /// See LabelInfo struct.
    label_info: Option<LabelInfo>,
    /// See ForwarderInfo struct.
    forwarder_info: Option<ForwarderInfo>,
}

/// The EncryptionInfo struct holds information about the encryption keys for the
/// recipient/sender of a resource in a transaction.
pub struct EncryptionInfo {
    /// Secret key. randomly generated for persistent resource_ciphertext
    pub sender_sk: EmbeddedCurveScalar,
    /// randomly generated for persistent resource_ciphertext(12 bytes)
    pub encryption_nonce: [u8; ENCRYPTION_NONCE_LEN],
    /// The discovery ciphertext for the resource
    discovery_ciphertext: [u8; MAX_DISCOVERY_CIPHERTEXT_LEN],
    discovery_ciphertext_len: u32,
}

/// ValueInfo holds information about value plaintext
pub struct ValueInfo {
    /// The authorization verifying key corresponds to the resource.value.owner
    auth_pk: [u8; MAX_AUTH_PK_LEN],
    /// Public key. Obtain from the receiver for persistent resource_ciphertext
    encryption_pk: EmbeddedCurvePoint,
}

/// An expirable blob consists of a blob and a deletion criterion.
struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    blob: [u8; MAX_BLOB_LEN],
    blob_len: u32,
    /// The deletion criterion for the blob.
    deletion_criterion: bool,
}

/// The struct encoded in the resource payload for persistent created resources.
pub struct ResourceWithLabel {
    pub resource: Resource,
    /// Address of the forwarder contract for this resource.
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    /// Address of the wrapped token within this resource (e.g. USDC).
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
}

impl ResourceWithLabel {
    fn to_bytes(self) -> [u8; RESOURCE_WITH_LABEL_BYTES] {
        // Concatenate all the components of this resource
        let mut bytes = [0; RESOURCE_WITH_LABEL_BYTES];
        let mut offset: u32 = 0;
        // Write the resource bytes
        write_bytes(&mut bytes, &mut offset, self.resource.to_bytes());
        // Write the forwarder address bytes
        write_bytes(&mut bytes, &mut offset, self.forwarder_addr);
        // Write the token address bytes
        write_bytes(&mut bytes, &mut offset, self.erc20_token_addr);
        static_assert(offset == RESOURCE_WITH_LABEL_BYTES, "resource with label bytes malformed");
        bytes
    }
}

/// Application data contains four different types of payloads.
struct AppData {
    /// The resource payload blobs.
    resource_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    resource_payload_len: u32,
    /// The application payload blobs.
    application_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    application_payload_len: u32,
    /// The external payload blobs.
    external_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    external_payload_len: u32,
    /// The discovery payload blobs.
    discovery_payload: [ExpirableBlob; MAX_BLOBS_PER_PAYLOAD],
    discovery_payload_len: u32,
}

impl AppData {
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
struct ResourceLogicInstance {
    /// The logic instance's tag (either commitment or nullifier)
    tag: [u8; DIGEST_BYTES],
    /// The root digest of the logic instance.
    action_root: [u8; DIGEST_BYTES],
    /// Indicates whether the logic instance is for a consumed resource.
    is_consumed: bool,
    /// The application data associated with the logic instance.
    app_data: AppData,
}

impl ResourceLogicInstance {
    fn digest(self) -> Field {
        let mut buf = [0; MAX_LOGIC_DIGEST_BUF_LEN];
        let mut buf_len = 0;
        write_bytes(&mut buf, &mut buf_len, self.tag);
        write_bytes(&mut buf, &mut buf_len, self.action_root);
        write_bytes(&mut buf, &mut buf_len, [self.is_consumed as u8]);

        let lists = [
            (self.app_data.resource_payload, self.app_data.resource_payload_len),
            (self.app_data.application_payload, self.app_data.application_payload_len),
            (self.app_data.external_payload, self.app_data.external_payload_len),
            (self.app_data.discovery_payload, self.app_data.discovery_payload_len),
        ];

        for list_idx in 0..4 {
            let list = lists[list_idx].0;
            let list_len = lists[list_idx].1;
            
            let len_bytes = (list_len as Field).to_le_bytes::<PAYLOAD_LEN_BYTES>();
            write_bytes(&mut buf, &mut buf_len, len_bytes);

            for p_idx in 0..MAX_BLOBS_PER_PAYLOAD {
                let p = list[p_idx];
                let p_len_bytes = (p.blob_len as Field).to_le_bytes::<BLOB_LEN_BYTES>();
                write_bytes(&mut buf, &mut buf_len, p_len_bytes);
                write_bytes(&mut buf, &mut buf_len, p.blob);
                write_bytes(&mut buf, &mut buf_len, [p.deletion_criterion as u8]);
            }
        }
        static_assert(buf_len == MAX_LOGIC_DIGEST_BUF_LEN, "logic instance digest pre-image malformed");
        Field::from_le_bytes(keccak256::keccak256(buf, buf_len))
    }
}

/// Calculate the label ref based on the forwarded and token address for resources.
fn calculate_label_ref(
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
) -> [u8; 32] {
    let mut bytes = [0; MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN];
    let mut offset = 0;
    write_bytes(&mut bytes, &mut offset, forwarder_addr);
    write_bytes(&mut bytes, &mut offset, erc20_token_addr);
    static_assert(offset == MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN, "label reference pre-image malformed");
    keccak256::keccak256(bytes, offset)
}

/// Calculate the value ref based on an authorization key and an encryption key for a given user.
fn persistent_value_ref(
    auth_pk: [u8; MAX_AUTH_PK_LEN],
    encryption_pk: EmbeddedCurvePoint,
) -> [u8; 32] {
    let mut bytes = [0; MAX_AUTH_PK_LEN + 2*EMBEDDED_CURVE_BASE_FIELD_BYTES];
    let mut offset = 0;
    write_bytes(&mut bytes, &mut offset, auth_pk);
    write_bytes(&mut bytes, &mut offset, encryption_pk.x.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
    write_bytes(&mut bytes, &mut offset, encryption_pk.y.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
    static_assert(offset == MAX_AUTH_PK_LEN + 2*EMBEDDED_CURVE_BASE_FIELD_BYTES, "value reference pre-image malformed");
    keccak256::keccak256(bytes, offset)
}

/// Create the value_ref for the user's ethereum account address.
fn value_ref_from_eth_addr(ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN]) -> [u8; DIGEST_BYTES] {
    let mut value_ref = [0; 32];
    let mut offset = 0;
    write_bytes(&mut value_ref, &mut offset, ethereum_account_addr);
    value_ref
}

fn encode_wrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    quantity: u128,
    nonce: [u8; MAX_PERMIT_NONCE_LEN],
    deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    action_tree_root: [u8; 32],
    signature: [u8; MAX_PERMIT_SIG_LEN],
) -> ([u8; MAX_INPUT_LEN], u32) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: u32 = 0;
    write_bytes(&mut res, &mut offset, [CALL_TYPE_WRAP]);
    write_bytes(&mut res, &mut offset, erc20_token_addr);
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = (quantity as Field).to_be_bytes::<QUANTITY_BYTES>();
    write_bytes(&mut res, &mut offset, quantity_bytes);
    write_bytes(&mut res, &mut offset, nonce);
    write_bytes(&mut res, &mut offset, deadline);
    write_bytes(&mut res, &mut offset, ethereum_account_addr);
    write_bytes(&mut res, &mut offset, action_tree_root);
    write_bytes(&mut res, &mut offset, signature);
    
    (res, offset)
}

fn encode_unwrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    quantity: u128,
) -> ([u8; MAX_INPUT_LEN], u32) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: u32 = 0;
    write_bytes(&mut res, &mut offset, [CALL_TYPE_UNWRAP]);
    write_bytes(&mut res, &mut offset, erc20_token_addr);
    write_bytes(&mut res, &mut offset, ethereum_account_addr);
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = (quantity as Field).to_be_bytes::<QUANTITY_BYTES>();
    write_bytes(&mut res, &mut offset, quantity_bytes);
    (res, offset)
}

fn encode_forwarder_calldata(
    forwarder: [u8; MAX_FORWARDER_ADDR_LEN],
    input: [u8; MAX_INPUT_LEN],
    output: [u8; MAX_OUTPUT_LEN],
) -> ([u8; MAX_FORWARDER_CALLDATA_LEN], u32) {
    let mut res = [0; MAX_FORWARDER_CALLDATA_LEN];
    let mut offset: u32 = 0;
    write_bytes(&mut res, &mut offset, forwarder);
    write_bytes(&mut res, &mut offset, input);
    write_bytes(&mut res, &mut offset, output);
    (res, offset)
}

// Mock signature verification. In real Noir, use std::ecdsa_secp256k1::verify_signature.
fn verify_prehash(
    pk: [u8; MAX_AUTH_PK_LEN],
    sig: [u8; MAX_AUTH_SIG_LEN],
    message_hash: [u8; 32],
) -> bool {
    assert(pk[0] == 0x04);
    let mut pk_x = [0; 32];
    for i in 0..32 { pk_x[i] = pk[1+i]; }
    let mut pk_y = [0; 32];
    for i in 0..32 { pk_y[i] = pk[33+i]; }
    std::ecdsa_secp256k1::verify_signature(pk_x, pk_y, sig, message_hash)
}

impl TransferAuthWitness {
    // Compute the tag
    fn tag(self) -> [u8; DIGEST_BYTES] {
        if self.is_consumed {
            let nk = self.nullifier_key.unwrap();
            self.resource.nullifier(nk)
        } else {
            self.resource.commitment()
        }
    }

    fn _constrain(self) -> ResourceLogicInstance {
        // Load resources
        let tag = self.tag();
        // Generate payloads
        let app_data = if self.resource.is_ephemeral {
            // Generate external_payload for the ephemeral resource
            self.ephemeral_resource_check()
        } else if self.is_consumed {
            // Consume a persistent resource
            self.persistent_consume()
        } else {
            // Create a persistent resource
            self.persistent_create()
        };
        
        ResourceLogicInstance {
            tag: tag,
            action_root: self.action_root,
            is_consumed: self.is_consumed,
            app_data: app_data,
        }
    }

    // check on ephemeral resources and return external_payload
    fn ephemeral_resource_check(self) -> AppData {
        let forwarder = self.forwarder_info.unwrap();
        let label = self.label_info.unwrap();
        // Check resource label: label = keccak(forwarder_addr, erc20_token_addr)
        let expected_label_ref = calculate_label_ref(
            label.forwarder_addr,
            label.erc20_token_addr,
        );
        assert(self.resource.label_ref == expected_label_ref);

        let mut input = [0; MAX_INPUT_LEN];
        let mut input_len = 0;

        if self.is_consumed {
            // Wrap
            assert(forwarder.call_type as u8 == CALL_TYPE_WRAP);
            let permit = forwarder.permit.unwrap();
            let (enc_input, enc_len) = encode_wrap_forwarder_input(
                label.erc20_token_addr,
                self.resource.quantity,
                permit.permit_nonce,
                permit.permit_deadline,
                forwarder.ethereum_account_addr,
                self.action_root,
                permit.permit_sig,
            );
            input = enc_input;
            input_len = enc_len;
        } else {
            // Unwrap
            assert(forwarder.call_type as u8 == CALL_TYPE_UNWRAP);
            let expected_value_ref = value_ref_from_eth_addr(
                forwarder.ethereum_account_addr,
            );
            assert(self.resource.value_ref == expected_value_ref);
            
            let (enc_input, enc_len) = encode_unwrap_forwarder_input(
                label.erc20_token_addr,
                forwarder.ethereum_account_addr,
                self.resource.quantity,
            );
            input = enc_input;
            input_len = enc_len;
        }

        let (data, data_len) = encode_forwarder_calldata(
            label.forwarder_addr,
            input,
            [0; MAX_OUTPUT_LEN],
        );

        let mut app_data = AppData::default();
        app_data.external_payload[0] = ExpirableBlob {
            blob: data,
            blob_len: data_len,
            deletion_criterion: false,
        };
        app_data.external_payload_len = 1;
        app_data
    }

    // check persistent resource consumption
    fn persistent_consume(self) -> AppData {
        let value_info = self.value_info.unwrap();
        let sig = self.auth_sig.unwrap();

        let expected_value_ref = persistent_value_ref(
            value_info.auth_pk,
            value_info.encryption_pk,
        );
        assert(self.resource.value_ref == expected_value_ref);

        // Verify the authorization signature
        let is_valid = verify_prehash(
            value_info.auth_pk,
            sig,
            self.action_root,
        );
        assert(is_valid);

        AppData::default()
    }

    // check persistent resource creation and return discovery_payload and resource_payload
    fn persistent_create(self) -> AppData {
        let value_info = self.value_info.unwrap();
        let label = self.label_info.unwrap();
        let encryption_info = self.encryption_info.unwrap();

        let expected_label_ref = calculate_label_ref(
            label.forwarder_addr,
            label.erc20_token_addr,
        );
        assert(self.resource.label_ref == expected_label_ref);

        let expected_value_ref = persistent_value_ref(
            value_info.auth_pk,
            value_info.encryption_pk,
        );
        assert(self.resource.value_ref == expected_value_ref);

        let payload_plaintext = ResourceWithLabel {
            resource: self.resource,
            forwarder_addr: label.forwarder_addr,
            erc20_token_addr: label.erc20_token_addr,
        }.to_bytes();

        assert(!value_info.encryption_pk.is_infinite());
        let shared_point = multi_scalar_mul([value_info.encryption_pk], [encryption_info.sender_sk]);
        let mut concat = [0u8; 4*EMBEDDED_CURVE_BASE_FIELD_BYTES];
        let mut offset: u32 = 0;
        write_bytes(&mut concat, &mut offset, value_info.encryption_pk.x.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        write_bytes(&mut concat, &mut offset, value_info.encryption_pk.y.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        write_bytes(&mut concat, &mut offset, shared_point.x.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        write_bytes(&mut concat, &mut offset, shared_point.y.to_le_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        let hash = keccak256::keccak256(concat, offset);
        let mut hash_prefix = [0u8; 16];
        for i in 0..hash_prefix.len() { hash_prefix[i] = hash[i]; }
        let mut encryption_nonce = [0u8; 16];
        for i in 0..encryption_info.encryption_nonce.len() { encryption_nonce[i] = encryption_info.encryption_nonce[i]; }
        let ciphertext = aes128_encrypt(payload_plaintext, encryption_nonce, hash_prefix);
        let mut ciphertext_padded = [0u8; MAX_RESOURCE_CIPHERTEXT_LEN];
        let mut offset: u32 = 0;
        write_bytes(&mut ciphertext_padded, &mut offset, encryption_info.encryption_nonce);
        write_bytes(&mut ciphertext_padded, &mut offset, [0x04]);
        let sender_pk = fixed_base_scalar_mul(encryption_info.sender_sk);
        write_bytes(&mut ciphertext_padded, &mut offset, sender_pk.x.to_be_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        write_bytes(&mut ciphertext_padded, &mut offset, sender_pk.y.to_be_bytes::<EMBEDDED_CURVE_BASE_FIELD_BYTES>());
        write_bytes(&mut ciphertext_padded, &mut offset, ciphertext);

        let mut app_data = AppData::default();
        // Generate resource_payload
        app_data.resource_payload[0] = ExpirableBlob {
            blob: ciphertext_padded,
            blob_len: offset,
            deletion_criterion: true,
        };
        app_data.resource_payload_len = 1;
        // Generate discovery_payload
        let encryption_info = self.encryption_info.unwrap();
        app_data.discovery_payload[0] = ExpirableBlob {
            blob: encryption_info.discovery_ciphertext,
            blob_len: encryption_info.discovery_ciphertext_len,
            deletion_criterion: true,
        };
        app_data.discovery_payload_len = 1;

        app_data
    }
}

fn main(witness: TransferAuthWitness) -> pub Field {
    witness._constrain().digest()
}

#[test]
fn test_persistent_consume() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            label_ref: [0; DIGEST_BYTES],
            value_ref: [
                127, 100, 166, 39, 85, 162, 122, 34, 202, 242, 150, 61, 161, 163, 68, 189,
                34, 24, 117, 228, 6, 212, 12, 57, 246, 47, 237, 84, 165, 140, 105, 53,
            ],
            quantity: 0,
            nonce: [0; 32],
            nk_commitment: [
                41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200,
                75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99
            ],
            is_ephemeral: false,
        },
        is_consumed: true,
        action_root: [0; 32],
        nullifier_key: Option::some(NullifierKey { bytes: [0; 32] }),
        value_info: Option::some(ValueInfo {
            auth_pk: [
                0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
                0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
                0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
                0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
            ],
            encryption_pk: EmbeddedCurvePoint::generator(),
        }),
        auth_sig: Option::some([
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ]),
        encryption_info: Option::none(),
        label_info: Option::none(),
        forwarder_info: Option::none(),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == Field::from_le_bytes([
        231, 55, 255, 55, 84, 255, 114, 13, 199, 12, 233, 5, 228, 52, 72, 46,
        9, 52, 54, 247, 30, 240, 78, 16, 9, 4, 227, 58, 146, 238, 220, 33,
    ]));
}

#[test]
fn test_persistent_create() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            label_ref: [
                218, 167, 116, 38, 195, 12, 2, 164, 61, 159, 186, 78, 132, 26, 101, 86,
                197, 36, 212, 112, 48, 118, 46, 177, 77, 196, 175, 137, 126, 96, 93, 155
            ],
            value_ref: [
                145, 125, 108, 226, 176, 45, 216, 10, 89, 58, 221, 126, 129, 65, 107, 75,
                12, 86, 104, 19, 87, 226, 72, 24, 211, 206, 46, 220, 171, 170, 222, 238,
            ],
            quantity: 0,
            nonce: [0; 32],
            nk_commitment: [
                41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200,
                75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99
            ],
            is_ephemeral: false,
        },
        is_consumed: false,
        action_root: [0; 32],
        nullifier_key: Option::none(), // Not required for resource creation
        value_info: Option::some(ValueInfo {
            auth_pk: [0; MAX_AUTH_PK_LEN],
            encryption_pk: EmbeddedCurvePoint::generator(),
        }),
        auth_sig: Option::none(), // Not required for resource creation
        encryption_info: Option::some(EncryptionInfo {
            sender_sk: EmbeddedCurveScalar::new(0, 0),
            encryption_nonce: [0; ENCRYPTION_NONCE_LEN],
            discovery_ciphertext: [0; MAX_DISCOVERY_CIPHERTEXT_LEN],
            discovery_ciphertext_len: 0,
        }),
        label_info: Option::some(LabelInfo {
            forwarder_addr: [0; MAX_FORWARDER_ADDR_LEN],
            erc20_token_addr: [0; MAX_ERC20_TOKEN_ADDR_LEN],
        }),
        forwarder_info: Option::none(),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == Field::from_le_bytes([
        152, 67, 97, 157, 206, 101, 162, 166, 215, 221, 218, 58, 229, 89, 101, 246,
        29, 229, 183, 10, 80, 43, 57, 10, 220, 235, 221, 90, 186, 168, 23, 31,
    ]));
}

#[test]
fn test_ephemeral_wrap() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            // label_ref matches calculate_label_ref([0; 20], [0; 20])
            label_ref: [
                218, 167, 116, 38, 195, 12, 2, 164, 61, 159, 186, 78, 132, 26, 101, 86,
                197, 36, 212, 112, 48, 118, 46, 177, 77, 196, 175, 137, 126, 96, 93, 155
            ],
            value_ref: [0; DIGEST_BYTES],
            quantity: 0,
            nonce: [0; 32],
            // nk_commitment matches keccak256 of the NullifierKey [0; 32]
            nk_commitment: [
                41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200,
                75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99
            ],
            is_ephemeral: true, // Crucial for ephemeral logic
        },
        is_consumed: true, // Crucial for triggering the WRAP condition
        action_root: [0; 32],
        nullifier_key: Option::some(NullifierKey { bytes: [0; 32] }),
        value_info: Option::none(),
        auth_sig: Option::none(),
        encryption_info: Option::none(),
        label_info: Option::some(LabelInfo {
            forwarder_addr: [0; MAX_FORWARDER_ADDR_LEN],
            erc20_token_addr: [0; MAX_ERC20_TOKEN_ADDR_LEN],
        }),
        forwarder_info: Option::some(ForwarderInfo {
            call_type: CALL_TYPE_WRAP,
            ethereum_account_addr: [0; MAX_ETH_ADDR_LEN],
            permit: Option::some(PermitInfo {
                permit_nonce: [0; MAX_PERMIT_NONCE_LEN],
                permit_deadline: [0; MAX_PERMIT_DEADLINE_LEN],
                permit_sig: [0; MAX_PERMIT_SIG_LEN],
            }),
        }),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == Field::from_le_bytes([
        44, 21, 203, 216, 100, 62, 14, 92, 78, 168, 56, 112, 27, 62, 16, 118,
        45, 96, 178, 0, 107, 147, 59, 182, 118, 49, 41, 84, 125, 131, 96, 18
    ]));
}

#[test]
fn test_ephemeral_unwrap() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            // label_ref matches calculate_label_ref([0; 20], [0; 20])
            label_ref: [
                218, 167, 116, 38, 195, 12, 2, 164, 61, 159, 186, 78, 132, 26, 101, 86,
                197, 36, 212, 112, 48, 118, 46, 177, 77, 196, 175, 137, 126, 96, 93, 155
            ],
            // value_ref matches value_ref_from_eth_addr([0; 20])
            value_ref: [0; DIGEST_BYTES],
            quantity: 0,
            nonce: [0; 32],
            // nk_commitment matches keccak256 of the NullifierKey [0; 32]
            nk_commitment: [
                41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200,
                75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99
            ],
            is_ephemeral: true, // Crucial for ephemeral logic
        },
        is_consumed: false, // Crucial for triggering the UNWRAP condition
        action_root: [0; 32],
        nullifier_key: Option::none(), // Not required for resource creation/unwrapping
        value_info: Option::none(),
        auth_sig: Option::none(),
        encryption_info: Option::none(),
        label_info: Option::some(LabelInfo {
            forwarder_addr: [0; MAX_FORWARDER_ADDR_LEN],
            erc20_token_addr: [0; MAX_ERC20_TOKEN_ADDR_LEN],
        }),
        forwarder_info: Option::some(ForwarderInfo {
            call_type: CALL_TYPE_UNWRAP,
            ethereum_account_addr: [0; MAX_ETH_ADDR_LEN],
            permit: Option::none(), // Permit is not required for an unwrap
        }),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == Field::from_le_bytes([
        84, 111, 49, 83, 109, 115, 229, 73, 212, 165, 27, 60, 22, 175, 126, 168,
        39, 245, 252, 90, 166, 76, 248, 249, 22, 135, 7, 128, 29, 126, 131, 143
    ]));
}
