use std::option::Option;
use std::static_assert;

// Constants for bounding unbounded loops and variable-length arrays
global MAX_FORWARDER_ADDR_LEN: u32 = 20;
global MAX_ERC20_TOKEN_ADDR_LEN: u32 = 20;
global MAX_ETH_ADDR_LEN: u32 = 20;
global MAX_AUTH_PK_LEN: u32 = 65;
global MAX_AUTH_SIG_LEN: u32 = 64;
global MAX_ENCRYPTION_PAYLOAD_LEN: u32 = 256;
global MAX_DISCOVERY_PAYLOAD_LEN: u32 = 256;
global MAX_PERMIT_NONCE_LEN: u32 = 32;
global MAX_PERMIT_DEADLINE_LEN: u32 = 32;
global MAX_PERMIT_SIG_LEN: u32 = 65;
global MAX_INPUT_LEN: u32 = 512;
global MAX_OUTPUT_LEN: u32 = 512;
global MAX_FORWARDER_CALLDATA_LEN: u32 = 256;
global MAX_PAYLOADS_PER_LIST: u32 = 1;
global MAX_PAYLOAD_DATA_LEN: u32 = 256;
global MAX_LOGIC_DIGEST_BUF_LEN: u32 = 1125;
global CALL_TYPE_WRAP: u8 = 0;
global CALL_TYPE_UNWRAP: u8 = 1;
global PRF_EXPAND_PERSONALIZATION_LEN: u32 = 16;
global PRF_EXPAND_PERSONALIZATION: [u8; PRF_EXPAND_PERSONALIZATION_LEN] = "RISC0_ExpandSeed".as_bytes();
global DIGEST_BYTES: u32 = 32;
global QUANTITY_BYTES: u32 = 16;
global RESOURCE_BYTES: u32 = DIGEST_BYTES
    + DIGEST_BYTES
    + DIGEST_BYTES
    + QUANTITY_BYTES
    + 1
    + DIGEST_BYTES
    + DIGEST_BYTES;
global PSI_BYTES: u32 = PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES;
global PRF_EXPAND_PSI: u8 = 0;

/// Nullifier key
struct NullifierKey {
    bytes: [u8; DIGEST_BYTES],
}

impl NullifierKey {
    /// Compute the commitment to the nullifier key
    fn commit(self) -> [u8; DIGEST_BYTES] {
        keccak256::keccak256(self.bytes, DIGEST_BYTES)
    }
}

struct Resource {
    /// a succinct representation of the predicate associated with the resource
    logic_ref: [u8; DIGEST_BYTES],
    /// specifies the fungibility domain for the resource
    label_ref: [u8; DIGEST_BYTES],
    /// the fungible value reference of the resource
    value_ref: [u8; DIGEST_BYTES],
    /// number representing the quantity of the resource
    quantity: u128,
    /// guarantees the uniqueness of the resource computable components
    nonce: [u8; DIGEST_BYTES],
    /// commitment to nullifier key
    nk_commitment: [u8; DIGEST_BYTES],
    /// flag that reflects the resource ephemerality
    is_ephemeral: bool,
    /// randomness seed used to derive whatever randomness needed
    rand_seed: [u8; DIGEST_BYTES],
}

impl Resource {
    /// Compute the inner psi for the resource
    fn psi(self) -> [u8; DIGEST_BYTES] {
        let mut bytes = [0u8; PSI_BYTES];
        let mut offset: u32 = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        for i in 0..PRF_EXPAND_PERSONALIZATION_LEN { bytes[i] = PRF_EXPAND_PERSONALIZATION[i]; }
        offset += PRF_EXPAND_PERSONALIZATION_LEN;
        // Write the PRF_EXPAND_PSI
        bytes[offset] = PRF_EXPAND_PSI;
        offset += 1;
        // Write the random seed
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.rand_seed[i]; }
        offset += DIGEST_BYTES;
        // Write the nonce
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.nonce[i]; }
        offset += DIGEST_BYTES;
        static_assert(offset == PSI_BYTES, "resource psi pre-image malformed");
        keccak256::keccak256(bytes, PSI_BYTES)
    }
    
    fn to_bytes(self) -> [u8; RESOURCE_BYTES] {
        // Concatenate all the components of this resource
        let mut bytes = [0; RESOURCE_BYTES];
        let mut offset: u32 = 0;
        // Write the image ID bytes
        for i in 0..DIGEST_BYTES { bytes[i] = self.logic_ref[i]; }
        offset += DIGEST_BYTES;
        // Write the label_ref bytes
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.label_ref[i]; }
        offset += DIGEST_BYTES;
        // Write the fungible value_ref bytes
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.value_ref[i]; }
        offset += DIGEST_BYTES;
        // Write the quantity bytes
        let q_bytes = (self.quantity as Field).to_be_bytes::<QUANTITY_BYTES>();
        for i in 0..QUANTITY_BYTES { bytes[offset + i] = q_bytes[i]; }
        offset += QUANTITY_BYTES;
        // Write the nonce bytes
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.nonce[i]; }
        offset += DIGEST_BYTES;
        // Write the nullifier public key bytes
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.nk_commitment[i]; }
        offset += DIGEST_BYTES;
        // Write the ephemeral flag
        bytes[offset] = self.is_ephemeral as u8;
        offset += 1;
        static_assert(offset == RESOURCE_BYTES, "resource commitment pre-image malformed");
        bytes
    }

    /// Compute the commitment to the resource
    fn commit(self) -> [u8; DIGEST_BYTES] {
        // Now produce the hash
        keccak256::keccak256(self.to_bytes(), RESOURCE_BYTES)
    }

    /// Compute the nullifier of the resource
    fn nullify(self, nk: NullifierKey) -> [u8; DIGEST_BYTES] {
        // Make sure that the nullifier public key corresponds to the secret key
        assert(self.nk_commitment == nk.commit());
        let mut bytes = [0; 4 * DIGEST_BYTES];
        let mut offset: u32 = 0;
        // Write the resource commitment
        let c = self.commit();
        for i in 0..DIGEST_BYTES { bytes[offset + i] = c[i]; }
        offset += DIGEST_BYTES;
        // Write the nullifier secret key
        for i in 0..DIGEST_BYTES { bytes[offset + i] = nk.bytes[i]; }
        offset += DIGEST_BYTES;
        // Write the nonce
        for i in 0..DIGEST_BYTES { bytes[offset + i] = self.nonce[i]; }
        offset += DIGEST_BYTES;
        // Write psi
        let psi = self.psi();
        for i in 0..DIGEST_BYTES { bytes[offset + i] = psi[i]; }
        offset += DIGEST_BYTES;
        static_assert(offset == 4 * DIGEST_BYTES, "nullifier pre-image malformed");
        keccak256::keccak256(bytes, 4 * DIGEST_BYTES)
    }
}

struct LabelInfo {
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    forwarder_addr_len: u32,
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    erc20_token_addr_len: u32,
}

struct PermitInfo {
    permit_nonce: [u8; MAX_PERMIT_NONCE_LEN],
    permit_nonce_len: u32,
    permit_deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    permit_deadline_len: u32,
    permit_sig: [u8; MAX_PERMIT_SIG_LEN],
    permit_sig_len: u32,
}

struct ForwarderInfo {
    call_type: u8,
    hiding_logic_bytes: [u8; 32],
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    ethereum_account_addr_len: u32,
    permit: Option<PermitInfo>,
}

struct TransferAuthWitness {
    resource: Resource,
    is_consumed: bool,
    action_root: [u8; 32],
    nullifier_key: Option<NullifierKey>,
    auth_pk: Option<[u8; MAX_AUTH_PK_LEN]>,
    auth_pk_len: u32,
    auth_sig: Option<[u8; MAX_AUTH_SIG_LEN]>,
    auth_sig_len: u32,
    encryption_payload: Option<[u8; MAX_ENCRYPTION_PAYLOAD_LEN]>,
    encryption_payload_len: u32,
    discovery_payload: Option<[u8; MAX_DISCOVERY_PAYLOAD_LEN]>,
    discovery_payload_len: u32,
    label_info: Option<LabelInfo>,
    forwarder_info: Option<ForwarderInfo>,
}

struct Payload {
    data: [u8; MAX_PAYLOAD_DATA_LEN],
    data_len: u32,
    deletion_criterion: bool,
}

struct AppData {
    resource_payload: [Payload; MAX_PAYLOADS_PER_LIST],
    resource_payload_len: u32,
    encryption_payload: [Payload; MAX_PAYLOADS_PER_LIST],
    encryption_payload_len: u32,
    external_payload: [Payload; MAX_PAYLOADS_PER_LIST],
    external_payload_len: u32,
    discovery_payload: [Payload; MAX_PAYLOADS_PER_LIST],
    discovery_payload_len: u32,
}

impl AppData {
    fn default() -> Self {
        AppData {
            resource_payload: [Payload { data: [0; MAX_PAYLOAD_DATA_LEN], data_len: 0, deletion_criterion: false }; MAX_PAYLOADS_PER_LIST],
            resource_payload_len: 0,
            encryption_payload: [Payload { data: [0; MAX_PAYLOAD_DATA_LEN], data_len: 0, deletion_criterion: false }; MAX_PAYLOADS_PER_LIST],
            encryption_payload_len: 0,
            external_payload: [Payload { data: [0; MAX_PAYLOAD_DATA_LEN], data_len: 0, deletion_criterion: false }; MAX_PAYLOADS_PER_LIST],
            external_payload_len: 0,
            discovery_payload: [Payload { data: [0; MAX_PAYLOAD_DATA_LEN], data_len: 0, deletion_criterion: false }; MAX_PAYLOADS_PER_LIST],
            discovery_payload_len: 0,
        }
    }
}

struct ResourceLogicInstance {
    tag: [u8; 32],
    action_root: [u8; 32],
    is_consumed: bool,
    app_data: AppData,
}

impl ResourceLogicInstance {
    fn logic_digest(self) -> [u8; 32] {
        let mut buf = [0; MAX_LOGIC_DIGEST_BUF_LEN];
        let mut buf_len = 0;

        for i in 0..32 { buf[buf_len + i] = self.tag[i]; }
        buf_len += 32;
        for i in 0..32 { buf[buf_len + i] = self.action_root[i]; }
        buf_len += 32;
        buf[buf_len] = self.is_consumed as u8;
        buf_len += 1;

        let lists = [
            (self.app_data.resource_payload, self.app_data.resource_payload_len),
            (self.app_data.encryption_payload, self.app_data.encryption_payload_len),
            (self.app_data.external_payload, self.app_data.external_payload_len),
            (self.app_data.discovery_payload, self.app_data.discovery_payload_len),
        ];

        for list_idx in 0..4 {
            let list = lists[list_idx].0;
            let list_len = lists[list_idx].1;
            
            let len_bytes = (list_len as Field).to_le_bytes::<4>();
            for i in 0..4 { buf[buf_len + i] = len_bytes[i]; }
            buf_len += 4;

            for p_idx in 0..MAX_PAYLOADS_PER_LIST {
                let p = list[p_idx];
                let p_len_bytes = (p.data_len as Field).to_le_bytes::<4>();
                for i in 0..4 { buf[buf_len + i] = p_len_bytes[i]; }
                buf_len += 4;

                for i in 0..MAX_PAYLOAD_DATA_LEN {
                    buf[buf_len + i] = p.data[i];
                }
                buf_len += MAX_PAYLOAD_DATA_LEN;

                buf[buf_len] = p.deletion_criterion as u8;
                buf_len += 1;
            }
        }

        // Note: In a real Noir circuit, you would hash only the valid bytes up to buf_len.
        // This assumes std::hash::keccak256 can handle the buffer or a slice is used.
        keccak256::keccak256(buf, buf_len)
    }
}

// Helper functions for label and value refs
fn calculate_label_ref(
    forwarder_addr: [u8; MAX_FORWARDER_ADDR_LEN],
    forwarder_addr_len: u32,
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    erc20_token_addr_len: u32,
) -> [u8; 32] {
    let mut bytes = [0; MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN];
    for i in 0..MAX_FORWARDER_ADDR_LEN {
        bytes[i] = forwarder_addr[i];
    }
    for i in 0..MAX_ERC20_TOKEN_ADDR_LEN {
        bytes[MAX_FORWARDER_ADDR_LEN + i] = erc20_token_addr[i];
    }
    keccak256::keccak256(bytes, MAX_FORWARDER_ADDR_LEN + MAX_ERC20_TOKEN_ADDR_LEN)
}

fn persistent_value_ref(
    auth_pk: [u8; MAX_AUTH_PK_LEN],
    auth_pk_len: u32,
    encryption_payload: [u8; MAX_ENCRYPTION_PAYLOAD_LEN],
    encryption_payload_len: u32,
) -> [u8; 32] {
    let mut bytes = [0; MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PAYLOAD_LEN];
    for i in 0..MAX_AUTH_PK_LEN {
        bytes[i] = auth_pk[i];
    }
    for i in 0..MAX_ENCRYPTION_PAYLOAD_LEN {
        bytes[MAX_AUTH_PK_LEN + i] = encryption_payload[i];
    }
    keccak256::keccak256(bytes, MAX_AUTH_PK_LEN + MAX_ENCRYPTION_PAYLOAD_LEN)
}

fn value_ref_from_eth_addr(ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN], len: u32) -> [u8; 32] {
    let mut value_ref = [0; 32];
    for i in 0..MAX_ETH_ADDR_LEN {
        value_ref[i] = ethereum_account_addr[i];
    }
    value_ref
}

// Mock ABI encoding functions. In a real implementation, these would perform actual ABI encoding.
fn encode_wrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    erc20_token_addr_len: u32,
    quantity: u128,
    nonce: [u8; MAX_PERMIT_NONCE_LEN],
    nonce_len: u32,
    deadline: [u8; MAX_PERMIT_DEADLINE_LEN],
    deadline_len: u32,
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    ethereum_account_addr_len: u32,
    action_tree_root: [u8; 32],
    signature: [u8; MAX_PERMIT_SIG_LEN],
    signature_len: u32,
) -> ([u8; MAX_INPUT_LEN], u32) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: u32 = 0;

    for i in 0..MAX_ERC20_TOKEN_ADDR_LEN {
        res[offset + i] = erc20_token_addr[i];
    }
    offset += MAX_ERC20_TOKEN_ADDR_LEN;
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = (quantity as Field).to_be_bytes::<16>();
    for i in 0..16 { res[offset + i] = quantity_bytes[i]; }
    offset += 16;
    for i in 0..MAX_PERMIT_NONCE_LEN {
        res[offset + i] = nonce[i];
    }
    offset += MAX_PERMIT_NONCE_LEN;
    for i in 0..MAX_PERMIT_DEADLINE_LEN {
        res[offset + i] = deadline[i];
    }
    offset += MAX_PERMIT_DEADLINE_LEN;
    for i in 0..MAX_ETH_ADDR_LEN {
        res[offset + i] = ethereum_account_addr[i];
    }
    offset += MAX_ETH_ADDR_LEN;
    for i in 0..32 {
        res[offset + i] = action_tree_root[i];
    }
    offset += 32;
    for i in 0..MAX_PERMIT_SIG_LEN {
        res[offset + i] = signature[i];
    }
    offset += MAX_PERMIT_SIG_LEN;
    (res, offset)
}

fn encode_unwrap_forwarder_input(
    erc20_token_addr: [u8; MAX_ERC20_TOKEN_ADDR_LEN],
    erc20_token_addr_len: u32,
    ethereum_account_addr: [u8; MAX_ETH_ADDR_LEN],
    ethereum_account_addr_len: u32,
    quantity: u128,
) -> ([u8; MAX_INPUT_LEN], u32) {
    let mut res = [0; MAX_INPUT_LEN];
    let mut offset: u32 = 0;

    for i in 0..MAX_ERC20_TOKEN_ADDR_LEN {
        res[offset + i] = erc20_token_addr[i];
    }
    offset += MAX_ERC20_TOKEN_ADDR_LEN;
    for i in 0..MAX_ETH_ADDR_LEN {
        res[offset + i] = ethereum_account_addr[i];
    }
    offset += MAX_ETH_ADDR_LEN;
    // Convert u128 to 16 bytes (Big-Endian)
    let quantity_bytes = (quantity as Field).to_be_bytes::<16>();
    for i in 0..16 { res[offset + i] = quantity_bytes[i]; }
    offset += 16;
    (res, offset)
}

fn encode_forwarder_calldata(
    forwarder: [u8; MAX_FORWARDER_ADDR_LEN],
    forwarder_len: u32,
    logic_hiding_bytes: [u8; 32],
    input: [u8; MAX_INPUT_LEN],
    input_len: u32,
    output: [u8; MAX_OUTPUT_LEN],
    output_len: u32,
) -> ([u8; MAX_FORWARDER_CALLDATA_LEN], u32) {
    let mut res = [0; MAX_FORWARDER_CALLDATA_LEN];
    let mut offset: u32 = 0;

    for i in 0..MAX_FORWARDER_ADDR_LEN {
        res[offset + i] = forwarder[i];
    }
    offset += MAX_FORWARDER_ADDR_LEN;
    for i in 0..32 {
        res[offset + i] = logic_hiding_bytes[i];
    }
    offset += 32;
    for i in 0..MAX_INPUT_LEN {
        res[offset + i] = input[i];
    }
    offset += MAX_INPUT_LEN;
    for i in 0..MAX_OUTPUT_LEN {
        res[offset + i] = output[i];
    }
    offset += MAX_OUTPUT_LEN;
    (res, offset)
}

// Mock signature verification. In real Noir, use std::ecdsa_secp256k1::verify_signature.
fn verify_prehash(
    pk: [u8; MAX_AUTH_PK_LEN],
    pk_len: u32,
    sig: [u8; MAX_AUTH_SIG_LEN],
    sig_len: u32,
    message_hash: [u8; 32],
) -> bool {
    assert(pk[0] == 0x04);
    let mut pk_x = [0; 32];
    for i in 0..32 {
        pk_x[i] = pk[1+i];
    }
    let mut pk_y = [0; 32];
    for i in 0..32 {
        pk_y[i] = pk[33+i];
    }
    std::ecdsa_secp256k1::verify_signature(pk_x, pk_y, sig, message_hash)
}

impl TransferAuthWitness {
    fn tag(self) -> [u8; 32] {
        if self.is_consumed {
            let nk = self.nullifier_key.unwrap();
            self.resource.nullify(nk)
        } else {
            self.resource.commit()
        }
    }

    fn _constrain(self) -> ResourceLogicInstance {
        let tag = self.tag();
        let app_data = if self.resource.is_ephemeral {
            self.ephemeral_resource_check()
        } else if self.is_consumed {
            self.persistent_consume()
        } else {
            self.persistent_create()
        };
        
        ResourceLogicInstance {
            tag: tag,
            action_root: self.action_root,
            is_consumed: self.is_consumed,
            app_data: app_data,
        }
    }

    fn ephemeral_resource_check(self) -> AppData {
        let forwarder = self.forwarder_info.unwrap();
        let label = self.label_info.unwrap();

        let expected_label_ref = calculate_label_ref(
            label.forwarder_addr,
            label.forwarder_addr_len,
            label.erc20_token_addr,
            label.erc20_token_addr_len,
        );
        assert(self.resource.label_ref == expected_label_ref);

        let mut input = [0; MAX_INPUT_LEN];
        let mut input_len = 0;

        if self.is_consumed {
            assert(forwarder.call_type as u8 == CALL_TYPE_WRAP);
            let permit = forwarder.permit.unwrap();
            let (enc_input, enc_len) = encode_wrap_forwarder_input(
                label.erc20_token_addr,
                label.erc20_token_addr_len,
                self.resource.quantity,
                permit.permit_nonce,
                permit.permit_nonce_len,
                permit.permit_deadline,
                permit.permit_deadline_len,
                forwarder.ethereum_account_addr,
                forwarder.ethereum_account_addr_len,
                self.action_root,
                permit.permit_sig,
                permit.permit_sig_len,
            );
            input = enc_input;
            input_len = enc_len;
        } else {
            assert(forwarder.call_type as u8 == CALL_TYPE_UNWRAP);
            let expected_value_ref = value_ref_from_eth_addr(
                forwarder.ethereum_account_addr,
                forwarder.ethereum_account_addr_len,
            );
            assert(self.resource.value_ref == expected_value_ref);
            
            let (enc_input, enc_len) = encode_unwrap_forwarder_input(
                label.erc20_token_addr,
                label.erc20_token_addr_len,
                forwarder.ethereum_account_addr,
                forwarder.ethereum_account_addr_len,
                self.resource.quantity,
            );
            input = enc_input;
            input_len = enc_len;
        }

        let (data, data_len) = encode_forwarder_calldata(
            label.forwarder_addr,
            label.forwarder_addr_len,
            forwarder.hiding_logic_bytes,
            input,
            input_len,
            [0; MAX_OUTPUT_LEN],
            0,
        );

        let mut app_data = AppData::default();
        app_data.external_payload[0] = Payload {
            data: data,
            data_len: data_len,
            deletion_criterion: false,
        };
        app_data.external_payload_len = 1;
        app_data
    }

    fn persistent_consume(self) -> AppData {
        let pk = self.auth_pk.unwrap();
        let sig = self.auth_sig.unwrap();
        let payload = self.encryption_payload.unwrap();

        let expected_value_ref = persistent_value_ref(
            pk,
            self.auth_pk_len,
            payload,
            self.encryption_payload_len,
        );
        assert(self.resource.value_ref == expected_value_ref);

        let is_valid = verify_prehash(
            pk,
            self.auth_pk_len,
            sig,
            self.auth_sig_len,
            self.action_root,
        );
        assert(is_valid);

        AppData::default()
    }

    fn persistent_create(self) -> AppData {
        let pk = self.auth_pk.unwrap();
        let payload = self.encryption_payload.unwrap();
        let label = self.label_info.unwrap();

        let expected_label_ref = calculate_label_ref(
            label.forwarder_addr,
            label.forwarder_addr_len,
            label.erc20_token_addr,
            label.erc20_token_addr_len,
        );
        assert(self.resource.label_ref == expected_label_ref);

        let expected_value_ref = persistent_value_ref(
            pk,
            self.auth_pk_len,
            payload,
            self.encryption_payload_len,
        );
        assert(self.resource.value_ref == expected_value_ref);

        let mut app_data = AppData::default();
        
        app_data.resource_payload[0] = Payload {
            data: payload,
            data_len: self.encryption_payload_len,
            deletion_criterion: true,
        };
        app_data.resource_payload_len = 1;

        let discovery = self.discovery_payload.map_or([0u8; MAX_DISCOVERY_PAYLOAD_LEN], |d| d);
        let discovery_len = self.discovery_payload.map_or(0, |_| self.discovery_payload_len);

        app_data.discovery_payload[0] = Payload {
            data: discovery,
            data_len: discovery_len,
            deletion_criterion: true,
        };
        app_data.discovery_payload_len = 1;

        app_data
    }
}

fn main(witness: TransferAuthWitness, logic_digest: pub [u8; 32]) {
    let instance = witness._constrain();
    assert(instance.logic_digest() == logic_digest);
}

#[test]
fn test_main() {
    let witness = TransferAuthWitness {
        resource: Resource {
            rand_seed: [0; DIGEST_BYTES],
            logic_ref: [0; DIGEST_BYTES],
            label_ref: [0; DIGEST_BYTES],
            // Pre-computed Keccak-256 hash of empty bytes to match 0-length inputs
            value_ref: [
                201, 242, 80, 122, 186, 212, 36, 194, 132, 67, 20, 124, 121, 241, 85, 104,
                172, 58, 218, 44, 175, 40, 12, 41, 93, 204, 12, 204, 171, 61, 6, 20
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
        auth_pk: Option::some([0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8]),
        auth_pk_len: 0,
        auth_sig: Option::some([0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98]),
        auth_sig_len: 0,
        encryption_payload: Option::some([0; MAX_ENCRYPTION_PAYLOAD_LEN]),
        encryption_payload_len: 0,
        discovery_payload: Option::none(),
        discovery_payload_len: 0,
        label_info: Option::none(),
        forwarder_info: Option::none(),
    };
    let logic_digest = [
        39, 110, 63, 236, 226, 214, 21, 70, 120, 12, 13, 16, 208, 98, 80, 178,
        94, 227, 111, 20, 107, 195, 182, 199, 189, 210, 178, 85, 10, 137, 246, 74
    ];

    // Execute the main function which triggers _constrain()
    main(witness, logic_digest);
}
