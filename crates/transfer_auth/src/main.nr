use std::option::Option;
use std::static_assert;
use core::{write_bytes, NullifierKey, Resource};

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

/// ValueInfo holds information about value plaintext
pub struct ValueInfo {
    /// The authorization verifying key corresponds to the resource.value.owner
    auth_pk: [u8; MAX_AUTH_PK_LEN],
    /// Public key. Obtain from the receiver for persistent resource_ciphertext
    encryption_pk: [u8; MAX_ENCRYPTION_PK_LEN],
}

/// An expirable blob consists of a blob and a deletion criterion.
struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    blob: [u8; MAX_BLOB_LEN],
    blob_len: u32,
    /// The deletion criterion for the blob.
    deletion_criterion: bool,
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
    fn logic_digest(self) -> [u8; 32] {
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
        keccak256::keccak256(buf, buf_len)
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
    encryption_pk: [u8; MAX_ENCRYPTION_PK_LEN],
) -> [u8; 32] {
    let mut bytes = [0; MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PK_LEN];
    let mut offset = 0;
    write_bytes(&mut bytes, &mut offset, auth_pk);
    write_bytes(&mut bytes, &mut offset, encryption_pk);
    static_assert(offset == MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PK_LEN, "value reference pre-image malformed");
    keccak256::keccak256(bytes, offset)
}

/// Create the value_ref for the user's ethereum account address.
fn value_ref_from_eth_addr(ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN]) -> [u8; DIGEST_BYTES] {
    let mut value_ref = [0; 32];
    let mut offset = 0;
    write_bytes(&mut value_ref, &mut offset, ethereum_account_addr);
    value_ref
}

// Mock ABI encoding functions. In a real implementation, these would perform actual ABI encoding.
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
        let payload = self.resource_ciphertext.unwrap();
        let label = self.label_info.unwrap();

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

        let mut app_data = AppData::default();
        // Generate resource_payload
        app_data.resource_payload[0] = ExpirableBlob {
            blob: payload,
            blob_len: self.resource_ciphertext_len,
            deletion_criterion: true,
        };
        app_data.resource_payload_len = 1;
        // Generate discovery_payload
        let discovery_ciphertext = self.discovery_ciphertext.unwrap();
        app_data.discovery_payload[0] = ExpirableBlob {
            blob: discovery_ciphertext,
            blob_len: self.discovery_ciphertext_len,
            deletion_criterion: true,
        };
        app_data.discovery_payload_len = 1;

        app_data
    }
}

fn main(witness: TransferAuthWitness) -> pub [u8; DIGEST_BYTES] {
    witness._constrain().logic_digest()
}

#[test]
fn test_persistent_consume() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            label_ref: [0; DIGEST_BYTES],
            value_ref: [
                251, 115, 230, 34, 134, 135, 66, 60, 171, 246, 65, 210, 213, 104, 205, 204,
                207, 125, 253, 189, 44, 24, 199, 126, 89, 234, 46, 24, 182, 164, 120, 101
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
            encryption_pk: [0; MAX_ENCRYPTION_PK_LEN],
        }),
        auth_sig: Option::some([
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ]),
        resource_ciphertext: Option::some([0; MAX_RESOURCE_CIPHERTEXT_LEN]),
        resource_ciphertext_len: 0,
        discovery_ciphertext: Option::none(),
        discovery_ciphertext_len: 0,
        label_info: Option::none(),
        forwarder_info: Option::none(),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == [
        252, 103, 131, 249, 94, 98, 147, 61, 162, 216, 156, 182, 40, 228, 247, 247,
        182, 212, 178, 148, 148, 15, 17, 59, 25, 93, 153, 242, 152, 174, 95, 116
    ]);
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
                232, 189, 44, 167, 37, 59, 242, 117, 69, 20, 246, 67, 159, 172, 198, 103,
                100, 253, 216, 110, 55, 193, 136, 128, 218, 13, 220, 36, 214, 168, 161, 44
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
            encryption_pk: [0; MAX_ENCRYPTION_PK_LEN],
        }),
        auth_sig: Option::none(), // Not required for resource creation
        resource_ciphertext: Option::some([0; MAX_RESOURCE_CIPHERTEXT_LEN]),
        resource_ciphertext_len: 0,
        discovery_ciphertext: Option::some([0; MAX_DISCOVERY_CIPHERTEXT_LEN]),
        discovery_ciphertext_len: 0,
        label_info: Option::some(LabelInfo {
            forwarder_addr: [0; MAX_FORWARDER_ADDR_LEN],
            erc20_token_addr: [0; MAX_ERC20_TOKEN_ADDR_LEN],
        }),
        forwarder_info: Option::none(),
    };

    // Execute the main function which triggers _constrain()
    let logic_digest = main(witness);
    assert(logic_digest == [
        156, 48, 139, 117, 185, 218, 114, 133, 235, 229, 247, 18, 172, 167, 166, 246,
        77, 49, 37, 158, 5, 162, 108, 72, 45, 209, 172, 233, 137, 30, 110, 249
    ]);
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
        resource_ciphertext: Option::none(),
        resource_ciphertext_len: 0,
        discovery_ciphertext: Option::none(),
        discovery_ciphertext_len: 0,
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
    assert(logic_digest == [
        44, 21, 203, 216, 100, 62, 14, 92, 78, 168, 56, 112, 27, 62, 16, 118,
        45, 96, 178, 0, 107, 147, 59, 182, 118, 49, 41, 84, 125, 131, 96, 18
    ]);
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
        resource_ciphertext: Option::none(),
        resource_ciphertext_len: 0,
        discovery_ciphertext: Option::none(),
        discovery_ciphertext_len: 0,
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
    assert(logic_digest == [
        84, 111, 49, 83, 109, 115, 229, 73, 212, 165, 27, 60, 22, 175, 126, 168,
        39, 245, 252, 90, 166, 76, 248, 249, 22, 135, 7, 128, 29, 126, 131, 143
    ]);
}
