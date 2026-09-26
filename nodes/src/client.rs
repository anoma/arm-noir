use std::collections::BTreeSet;
use crate::types::Nullifier;
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::BTreeMap;
use crate::wallet::GRUMPKIN_PUBLIC_KEY_LEN;
use std::collections::HashMap;
use crate::merkle::CommitmentTree;
use crate::merkle::CmtNode;
use crate::wallet::ExtendedFullViewingKey;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::Backend;
use crate::verifier::ShieldedPool;
use crate::types::Ciphertext;
use crate::types::EmbeddedCurvePoint;
use k256::ecdh::diffie_hellman;
use alloy::primitives::keccak256;
use crate::types::ResourceWithLabel;
use crate::types::DISCOVERY_PK_LEN;
use crate::types::DISCOVERY_SHARED_POINT_LEN;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::types::AES_KEY_LEN;
use crate::types::MAX_TREE_DEPTH;
use crate::types::NullifierKey;
use nodes::pad_slice;
use crate::types::Resource;
use crate::types::TransferAuthWitness;
use crate::types::ValueInfo;
use crate::types::LabelInfo;
use crate::types::ForwarderInfo;
use crate::types::CALL_TYPE_WRAP;
use crate::types::CALL_TYPE_UNWRAP;
use crate::types::PermitInfo;
use noirc_abi::InputMap;
use crate::types::MAX_ETH_ADDR_LEN;
use crate::types::ConsumedResourceWitness;
use crate::types::MerklePath;
use acir::FieldElement;
use acir::AcirField;
use crate::types::COMPLIANCE_CIRCUIT_PATH;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;
use crate::types::ResourceLogicInstance;
use crate::types::AppData;
use crate::types::ExpirableBlob;
use crate::types::encode_wrap_forwarder_input;
use crate::types::encode_forwarder_calldata;
use crate::types::encode_unwrap_forwarder_input;
use crate::types::ConsumedResourcePublic;
use crate::types::EncryptionInfo;
use crate::types::DISCOVERY_NONCE_LEN;
use k256::SecretKey;
use std::cell::OnceCell;
use std::rc::Rc;
use crate::merkle::ActNode;
use rand::Rng;
use std::path::PathBuf;
use crate::types::MAX_CONSUMED;
use crate::types::MAX_CREATED;
use crate::types::ComplianceWitness;
use crate::types::ComplianceInstance;
use crate::types::DIGEST_BYTES;
use crate::types::CreatedResourcePublic;
use bn254_blackbox_solver::multi_scalar_mul;
use crate::types::EmbeddedCurveScalar;
use nodes::SignMagnitude;
use nodes::Promise;
use crate::types::FORWARDER_ADDR_LEN;
use crate::types::MAX_UNTAGGED_ENCRYPTION_PK_LEN;
use crate::types::MAX_AUTH_PK_LEN;
use nodes::BarretenbergCircuit;
use crate::wallet::ExtendedSpendingKey;
use crate::types::ERC20_TOKEN_ADDR_LEN;
use nodes::PromiseExt;
use crate::ERC20_FORWARDER_ADDRESS;
use alloy::primitives::Address;
use crate::TRANSFER_AUTH_CIRCUIT_PATH;
use crate::wallet::PaymentAddress;
use alloy::primitives::hex;
use crate::types::MAX_OUTPUT_LEN;

pub static INITIAL_ROOT: [u8; 32] =
    hex!("c9d5969b3cbdef3fe2f655d5b7644da065f6adab6e612236932bfc4412f46308");

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
// A resource machine transaction
pub struct Transaction {
    // Logic instances and their corresponding proofs
    pub logic_instances: Vec<(ResourceLogicInstance, Vec<Vec<u8>>)>,
    // The compliance instance
    pub compliance_instance: ComplianceInstance,
    // The compliance proof
    pub compliance_proof: Vec<Vec<u8>>,
    // Transaction signature
    pub signature: Option<(Vec<u8>, Vec<u8>)>,
}

// Data structure to facilitate building Transactions
pub struct TransactionBuilder {
    // The action root to be signed over
    action_root: Rc<OnceCell<[u8; DIGEST_BYTES]>>,
    // The consumed nullifiers
    consumed_nullifiers: [[u8; DIGEST_BYTES]; MAX_CONSUMED],
    // The consumed data
    consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    consumed_logics: [Promise<ResourceLogicInstance>; MAX_CONSUMED],
    consumed_logic_proofs: [Vec<Vec<u8>>; MAX_CONSUMED],
    consumed_witnesses: [Promise<TransferAuthWitness>; MAX_CONSUMED],
    consumed_count: u8,
    // The created data
    created_resources: [Resource; MAX_CREATED],
    created_publics: [CreatedResourcePublic; MAX_CREATED],
    created_logics: [Promise<ResourceLogicInstance>; MAX_CREATED],
    created_logic_proofs: [Vec<Vec<u8>>; MAX_CONSUMED],
    created_witnesses: [Promise<TransferAuthWitness>; MAX_CONSUMED],
    created_count: u8,
    // Quantity delta
    delta_map: BTreeMap<EmbeddedCurvePoint, SignMagnitude<u128>>,
    // Circuits required for building proofs
    pub logic_circuit: BarretenbergCircuit,
    pub compliance_circuit: BarretenbergCircuit,
}

impl TransactionBuilder {
    pub fn new<B: Backend>(api: &mut BarretenbergApi<B>) -> Self {
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
            action_root: Default::default(),
            consumed_nullifiers: Default::default(),
            consumed_data: Default::default(),
            consumed_publics: Default::default(),
            consumed_logics: std::array::from_fn(|_| Promise::default()),
            consumed_logic_proofs: Default::default(),
            consumed_witnesses: std::array::from_fn(|_| Promise::default()),
            consumed_count: 0,
            created_resources: Default::default(),
            created_publics: Default::default(),
            created_logics: std::array::from_fn(|_| Promise::default()),
            created_logic_proofs: Default::default(),
            created_witnesses: std::array::from_fn(|_| Promise::default()),
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

    pub fn add_shielded_input<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        tree: &mut CommitmentTree<CmtNode>,
        spending_key: ExtendedSpendingKey,
        note: Resource,
        position: usize,
    ) {
        if self.created_count > 0 {
            panic!("Transaction inputs cannot be added after transparent outputs");
        }
        // The value info
        let payment_addr = spending_key.to_viewing_key().to_payment_address();
        let value_info = ValueInfo {
            auth_pk: payment_addr.verifying_key.to_encoded_point(false).as_bytes().try_into().unwrap(),
            encryption_pk: payment_addr.encryption_public_key,
        };
        // The transfer authorization witness
        let action_root_clone = self.action_root.clone();
        let is_consumed = true;
        let logic_witness = Promise::delay(move || {
            // The action root
            let action_root: [u8; DIGEST_BYTES] = *action_root_clone.get().expect("action root must be initialized first");
            // Sign over the resource
            let auth_sig: Signature = spending_key.signing_key.sign_prehash(&action_root).expect("unable to sign resource");
            TransferAuthWitness {
                resource: note.clone(),
                is_consumed,
                action_root,
                nullifier_key: Some(NullifierKey { bytes: spending_key.nullifier_key.0 }),
                value_info: Some(value_info),
                encryption_info: None,
                label_info: None,
                auth_sig: Some(auth_sig.to_bytes().into()),
                forwarder_info: None,
            }
        });
        // Convert the Merkle path into the circuit's format
        let path = tree.path(api, position);
        let mut circuit_path = [(FieldElement::zero(), false); MAX_TREE_DEPTH];
        for (depth, sibling) in path.auth_path.iter().enumerate() {
            circuit_path[depth].0 = sibling.0.into_scalar();
            circuit_path[depth].1 = sibling.1;
        }
        // Compliance witness
        let compliance_witness = ConsumedResourceWitness {
            resource: note.clone(),
            nf_key: NullifierKey { bytes: spending_key.nullifier_key.0 },
            cm_merkle_path: MerklePath {
                path: circuit_path,
                depth: MAX_TREE_DEPTH,
            },
        };
        let resource_commitment = note.commitment();
        let resource_nullifier = note
            .nullifier_from_commitment(compliance_witness.nf_key, resource_commitment);
        let action_root_clone = self.action_root.clone();
        let logic_instance = Promise::delay(move || ResourceLogicInstance {
            tag: resource_nullifier,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            is_consumed,
            app_data: AppData::default(),
        });
        let commitment_tree_root = compliance_witness.cm_merkle_path.root(api, resource_commitment);
        let compliance_public = ConsumedResourcePublic {
            resource_nullifier,
            resource_logic_ref: note.logic_ref,
            commitment_tree_root,
        };

        self.consumed_data[usize::from(self.consumed_count)] = compliance_witness;
        self.consumed_nullifiers[usize::from(self.consumed_count)] = resource_nullifier;
        self.consumed_publics[usize::from(self.consumed_count)] = compliance_public;
        self.consumed_logics[usize::from(self.consumed_count)] = logic_instance;
        self.consumed_witnesses[usize::from(self.consumed_count)] = logic_witness;
        self.consumed_count += 1;
    }

    pub fn add_transparent_input(
        &mut self,
        rng: &mut impl Rng,
        logic_ref: [u8; DIGEST_BYTES],
        addr: Address,
        erc20_token_addr: Address,
        amount: u128,
    ) {
        if self.created_count > 0 {
            panic!("Transaction inputs cannot be added after transparent outputs");
        }
        // Compute the label reference
        let (label_info, label_ref) = Self::build_label_info(&ERC20_FORWARDER_ADDRESS, &erc20_token_addr);
        // Generate randomness for the construction of the resource
        let mut rand_seed = [0u8; DIGEST_BYTES];
        rng.fill(&mut rand_seed);
        let mut nonce = [0u8; DIGEST_BYTES];
        rng.fill(&mut nonce);
        // Generate a nullifier key
        let nullifier_key = crate::wallet::NullifierKey::random(rng);
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
        // The transfer authorization witness
        let action_root_clone = self.action_root.clone();
        let is_consumed = true;
        let logic_witness = Promise::delay(move || TransferAuthWitness {
            resource,
            is_consumed,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            nullifier_key: Some(NullifierKey { bytes: nullifier_key.0 }),
            value_info: None,
            encryption_info: None,
            label_info: Some(label_info),
            auth_sig: None,
            forwarder_info: Some(forwarder_info),
        });
        // Compliance witness
        let compliance_witness = ConsumedResourceWitness {
            resource,
            nf_key: NullifierKey { bytes: nullifier_key.0 },
            cm_merkle_path: MerklePath {
                path: [(FieldElement::zero(), false); MAX_TREE_DEPTH],
                depth: MAX_TREE_DEPTH,
            },
        };
        let resource_commitment = resource.commitment();
        let resource_nullifier = resource
            .nullifier_from_commitment(compliance_witness.nf_key, resource_commitment);
        let action_root_clone = self.action_root.clone();
        let logic_instance = Promise::delay(move || {
            // Encode forwarder calldata
            let (enc_input, enc_len) = encode_wrap_forwarder_input(
                label_info.erc20_token_addr,
                resource.quantity,
                permit_info.permit_nonce,
                permit_info.permit_deadline,
                forwarder_info.ethereum_account_addr,
                *action_root_clone.get().expect("action root must be initialized first"),
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
            ResourceLogicInstance {
                tag: resource_nullifier,
                action_root: *action_root_clone.get().expect("action root must be initialized first"),
                is_consumed,
                app_data,
            }
        });
        let compliance_public = ConsumedResourcePublic {
            resource_nullifier,
            resource_logic_ref: logic_ref,
            commitment_tree_root: INITIAL_ROOT,
        };

        self.consumed_data[usize::from(self.consumed_count)] = compliance_witness;
        self.consumed_nullifiers[usize::from(self.consumed_count)] = resource_nullifier;
        self.consumed_publics[usize::from(self.consumed_count)] = compliance_public;
        self.consumed_logics[usize::from(self.consumed_count)] = logic_instance;
        self.consumed_witnesses[usize::from(self.consumed_count)] = logic_witness;
        self.consumed_count += 1;
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
        let ciphertext = api.aes_encrypt(&plaintext, &nonce_padded, &hash[..AES_KEY_LEN], plaintext.len() as u32)
            .expect("unable to perform AES encryption")
            .ciphertext;
        (ciphertext, nonce)
    }

    pub fn add_shielded_output<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        rng: &mut (impl Rng + rand::CryptoRng),
        logic_ref: [u8; DIGEST_BYTES],
        payment_addr: &PaymentAddress,
        erc20_token_addr: Address,
        amount: u128,
    ) {
        // Compute the digest of the consumed nullifiers
        let consumed_nullifiers_digest = Resource::hash_nullifiers(self.consumed_nullifiers, self.consumed_count.into());
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
        let mut value_ref_bytes = [0; MAX_AUTH_PK_LEN + MAX_UNTAGGED_ENCRYPTION_PK_LEN];
        value_ref_bytes[..MAX_AUTH_PK_LEN].copy_from_slice(&value_info.auth_pk);
        value_ref_bytes[MAX_AUTH_PK_LEN..].copy_from_slice(&value_info.encryption_pk.to_bytes());
        let value_ref = keccak256(value_ref_bytes);
        // Derive the nonce
        let nonce = Resource::derive_nonce(u32::from(self.created_count), consumed_nullifiers_digest);
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
        let payload_plaintext = borsh::to_vec(&ResourceWithLabel {
            resource: resource,
            forwarder_addr: label_info.forwarder_addr,
            erc20_token_addr: label_info.erc20_token_addr,
        }).expect("Unable to serialize resource");
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
            discovery_ciphertext: pad_slice(&discovery_ciphertext),
            discovery_ciphertext_len: discovery_ciphertext.len() as u32,
            encryption_nonce,
            sender_sk,
        };
        // The transfer authorization witness
        let action_root_clone = self.action_root.clone();
        let is_consumed = false;
        let witness = Promise::delay(move || TransferAuthWitness {
            resource,
            is_consumed,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            nullifier_key: None,
            value_info: Some(value_info),
            encryption_info: Some(encryption_info),
            label_info: Some(label_info),
            auth_sig: None,
            forwarder_info: None,
        });
        // Construct the application data
        let mut app_data = AppData::default();
        // Generate resource_payload
        app_data.resource_payload[0] = ExpirableBlob {
            blob: pad_slice(&resource_ciphertext),
            blob_len: resource_ciphertext.len() as u32,
            deletion_criterion: true,
        };
        app_data.resource_payload_len = 1;
        // Generate discovery_payload
        app_data.discovery_payload[0] = ExpirableBlob {
            blob: pad_slice(&discovery_ciphertext),
            blob_len: discovery_ciphertext.len() as u32,
            deletion_criterion: true,
        };
        app_data.discovery_payload_len = 1;
        let resource_commitment = resource.commitment();
        // Finally construct the resource logic instance
        let action_root_clone = self.action_root.clone();
        let logic_instance = Promise::delay(move || ResourceLogicInstance {
            tag: resource_commitment,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            is_consumed,
            app_data,
        });
        let compliance_public = CreatedResourcePublic {
            resource_commitment,
            resource_logic_ref: logic_ref,
        };

        // Compliance witness
        self.created_resources[usize::from(self.created_count)] = resource;
        self.created_publics[usize::from(self.created_count)] = compliance_public;
        self.created_logics[usize::from(self.created_count)] = logic_instance;
        self.created_witnesses[usize::from(self.created_count)] = witness;
        self.created_count += 1;
    }

    pub fn add_transparent_output(
        &mut self,
        rng: &mut impl Rng,
        logic_ref: [u8; DIGEST_BYTES],
        addr: &Address,
        erc20_token_addr: Address,
        amount: u128,
    ) {
        // Compute the digest of the consumed nullifiers
        let consumed_nullifiers_digest = Resource::hash_nullifiers(self.consumed_nullifiers, self.consumed_count.into());
        // Compute the label reference
        let (label_info, label_ref) = Self::build_label_info(&ERC20_FORWARDER_ADDRESS, &erc20_token_addr);
        // Generate randomness for the construction of the resource
        let mut rand_seed = [0u8; DIGEST_BYTES];
        rng.fill(&mut rand_seed);
        // Generate a nullifier key
        let nullifier_key = crate::wallet::NullifierKey::random(rng);
        // Calculate ephemeral value reference
        let mut value_ref = [0u8; 32];
        value_ref[0..MAX_ETH_ADDR_LEN].copy_from_slice(addr.as_slice());
        // Derive the nonce
        let nonce = Resource::derive_nonce(u32::from(self.created_count), consumed_nullifiers_digest);
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
        let is_consumed = false;
        // The transfer authorization witness
        let action_root_clone = self.action_root.clone();
        let witness = Promise::delay(move || TransferAuthWitness {
            resource,
            is_consumed,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            nullifier_key: Some(NullifierKey { bytes: nullifier_key.0 }),
            value_info: None,
            encryption_info: None,
            label_info: Some(label_info),
            auth_sig: None,
            forwarder_info: Some(forwarder_info),
        });
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
        let resource_commitment = resource.commitment();
        let action_root_clone = self.action_root.clone();
        let logic_instance = Promise::delay(move || ResourceLogicInstance {
            tag: resource_commitment,
            action_root: *action_root_clone.get().expect("action root must be initialized first"),
            is_consumed,
            app_data,
        });
        let compliance_public = CreatedResourcePublic {
            resource_commitment,
            resource_logic_ref: logic_ref,
        };

        // Compliance witness
        self.created_resources[usize::from(self.created_count)] = resource;
        self.created_publics[usize::from(self.created_count)] = compliance_public;
        self.created_logics[usize::from(self.created_count)] = logic_instance;
        self.created_witnesses[usize::from(self.created_count)] = witness;
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

    pub fn build<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        rng: &mut impl Rng,
    ) -> Transaction {
        // Compute the action tree root
        let mut tags = vec![];
        for i in 0..usize::from(self.consumed_count) {
            tags.push(ActNode(self.consumed_publics[i].resource_nullifier));
        }
        for i in 0..usize::from(self.created_count) {
            tags.push(ActNode(self.created_publics[i].resource_commitment));
        }
        let action_tree_depth = if tags.len() == 1 {
            0
        } else {
            (tags.len() - 1).ilog2() as usize + 1
        };
        let action_root = CommitmentTree::new(&mut (), action_tree_depth, &tags).root(&mut ());
        self.action_root.set(action_root.0).expect("Unable to set action root");
        // Generate input logic proofs
        for i in 0..usize::from(self.consumed_count) {
            let logic_witness = &self.consumed_witnesses[i];
            let compliance_witness = self.consumed_data[i];
            let logic_instance = &self.consumed_logics[i];
            let compliance_public = self.consumed_publics[i];
            
            let mut input_map = InputMap::new();
            input_map.insert("witness".to_string(), (***logic_witness).into());
            // Compute the proof from the witness bytes
            let prove_response = self.logic_circuit.circuit_prove(api, input_map).unwrap();
            self.consumed_logic_proofs[i] = prove_response.proof;
            assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
            // Accumulate delta
            *self.delta_map.entry(compliance_witness.resource.kind(api)).or_default() += SignMagnitude::from(compliance_witness.resource.quantity);
        }
        // Generate output logic proofs
        for i in 0..usize::from(self.created_count) {
            let witness = &self.created_witnesses[i];
            let logic_instance = &self.created_logics[i];
            let compliance_public = self.created_publics[i];
            // Accumulate delta
            *self.delta_map.entry(witness.resource.kind(api)).or_default() -= SignMagnitude::from(witness.resource.quantity);
            let mut input_map = InputMap::new();
            input_map.insert("witness".to_string(), (***witness).into());
            // Compute the proof from the witness bytes
            let prove_response = self.logic_circuit.circuit_prove(api, input_map).unwrap();
            self.created_logic_proofs[i] = prove_response.proof;
            assert_eq!(prove_response.public_inputs[0].clone(), logic_instance.digest().to_be_bytes());
        }
        let (compliance_witness, compliance_instance) = self.build_compliance_artifacts(rng);
        let rcv = compliance_witness.rcv;
        let mut input_map = InputMap::new();
        input_map.insert("witness".to_string(), compliance_witness.into());
        // Compute the proof from the witness bytes
        let prove_response = self.compliance_circuit.circuit_prove(api, input_map).unwrap();
        assert_eq!(prove_response.public_inputs[0].clone(), compliance_instance.digest().to_be_bytes());
        let mut logic_instances = vec![];
        for idx in 0..usize::from(self.consumed_count) {
            logic_instances.push((**self.consumed_logics[idx], self.consumed_logic_proofs[idx].clone()));
        }
        for idx in 0..usize::from(self.created_count) {
            logic_instances.push((**self.created_logics[idx], self.created_logic_proofs[idx].clone()));
        }
        // Construct the transaction
        let mut tx = Transaction {
            logic_instances,
            compliance_instance,
            compliance_proof: prove_response.proof,
            signature: None,
        };
        let tx_bytes = borsh::to_vec(&tx).expect("unable to hash transaction");
        let tx_hash = keccak256(tx_bytes);
        let msg = FieldElement::from_le_bytes_reduce(&tx_hash.0);
        // Sign the transaction
        let mut sk = rcv.to_bytes();
        sk.reverse();
        let signature = api
            .schnorr_construct_signature(&msg.to_be_bytes(), &sk)
            .expect("unable to sign transaction");
        tx.signature = Some((signature.s, signature.e));
        tx
    }
}

// The client's view of the shielded pool
#[derive(Default, BorshSerialize, BorshDeserialize, Debug)]
pub struct ClientState {
    // The state of the current commitment tree
    pub tree: CommitmentTree<CmtNode>,
    // Map viewing keys to the notes they own
    pub pos_map: HashMap<ExtendedFullViewingKey, BTreeSet<u64>>,
    // Map nullifiers to note positions they nullify
    pub nf_map: HashMap<Nullifier, u64>,
    // Map note position to notes
    pub note_map: BTreeMap<u64, ResourceWithLabel>,
    // Set of spent note positions
    pub spent_notes: BTreeSet<u64>,
    // The pool's current position
    pub current_pos: u64,
}

impl ClientState {
    pub fn synchronize<B: Backend>(api: &mut BarretenbergApi<B>, pool: ShieldedPool, fvks: &[ExtendedFullViewingKey]) -> Self {
        let mut state = Self::default();
        // Track the encountered resource commitments
        let mut commitments = vec![];
        // Scan the notes in the queue
        for transaction in pool.transactions {
            for (logic_instance, _) in transaction.logic_instances {
                // Process only created resources
                if logic_instance.is_consumed { continue; }
                let app_data = logic_instance.app_data;
                for i in 0..app_data.discovery_payload_len {
                    // Attempt to deserialize resource ciphertext
                    let resource_payload = app_data.resource_payload[i as usize];
                    let Some(resource_ciphertext) = Ciphertext::<_, EmbeddedCurvePoint>::from_bytes(
                        &resource_payload.blob[..resource_payload.blob_len as usize],
                    ) else {
                        continue;
                    };
                    // Attempt to deserialize discovery ciphertext
                    let discovery_payload = app_data.discovery_payload[i as usize];
                    let Some(discovery_ciphertext) = Ciphertext::<_, k256::AffinePoint>::from_bytes(
                        &discovery_payload.blob[..discovery_payload.blob_len as usize],
                    ) else {
                        continue;
                    };
                    for fvk in fvks {
                        // Attempt to decrypt discovery payload
                        let discovery_shared_point = diffie_hellman(fvk.discovery_secret_key.to_nonzero_scalar(), discovery_ciphertext.pk);
                        let discovery_public_key = fvk.discovery_secret_key.public_key().to_encoded_point(false);
                        let mut discovery_concat = [0u8; DISCOVERY_PK_LEN + DISCOVERY_SHARED_POINT_LEN];
                        discovery_concat[..DISCOVERY_PK_LEN].copy_from_slice(&discovery_public_key.as_bytes());
                        discovery_concat[DISCOVERY_PK_LEN..].copy_from_slice(&discovery_shared_point.raw_secret_bytes());
                        let key = &keccak256(discovery_concat)[..AES_KEY_LEN];
                        let nonce_padded = pad_slice::<16>(&discovery_ciphertext.nonce);
                        let plaintext = api.aes_decrypt(
                            &discovery_ciphertext.cipher,
                            &nonce_padded,
                            key,
                            discovery_ciphertext.cipher.len() as u32,
                        )
                            .expect("unable to perform AES decryption")
                            .plaintext;
                        // Padding scheme does not allow empty plaintexts
                        if plaintext.len() == 0 { continue }
                        // Grab the filler byte
                        let remainder = plaintext[plaintext.len() - 1];
                        // Ensure that the filler byte from the acceptable range
                        if remainder == 0 || remainder > 16 || usize::from(remainder) > plaintext.len() { continue }
                        // Ensure that the filler byte is consistently applied
                        if plaintext[plaintext.len() - usize::from(remainder)..].iter().any(|&b| b != remainder) {
                            continue;
                        }
                        // Finally, remove the padding
                        let plaintext = &plaintext[..plaintext.len() - usize::from(remainder)];

                        // Malformed payload, so skip resource decryption
                        if plaintext != [0x00] { continue }

                        // Attempt to decrypt resource payload
                        let resource_shared_point = resource_ciphertext.pk * fvk.encryption_secret_key;
                        let encryption_pk = EmbeddedCurvePoint::generator() * fvk.encryption_secret_key;
                        let mut encryption_concat = [0u8; 2*GRUMPKIN_PUBLIC_KEY_LEN];
                        encryption_concat[..GRUMPKIN_PUBLIC_KEY_LEN].copy_from_slice(&encryption_pk.to_bytes());
                        encryption_concat[GRUMPKIN_PUBLIC_KEY_LEN..].copy_from_slice(&resource_shared_point.to_bytes());
                        let key = &keccak256(encryption_concat)[..AES_KEY_LEN];
                        let nonce_padded = pad_slice::<16>(&resource_ciphertext.nonce);
                        let plaintext = api.aes_decrypt(
                            &resource_ciphertext.cipher,
                            &nonce_padded,
                            key,
                            resource_ciphertext.cipher.len() as u32,
                        )
                            .expect("unable to perform AES decryption")
                            .plaintext;
                        let remainder = plaintext[plaintext.len() - 1];
                        let plaintext = &plaintext[..plaintext.len() - usize::from(remainder)];

                        // Deserialize and store the decrypted resource
                        let Ok(resource) = ResourceWithLabel::try_from_slice(&plaintext) else { continue };
                        state.note_map.insert(state.current_pos, resource);
                    }
                }
                // Record the encountered resource commitment
                commitments.push(CmtNode::new(logic_instance.tag));
                // Update the note counter
                state.current_pos += 1;
            }
        }
        // Finally construct the tree
        state.tree = CommitmentTree::new(api, MAX_TREE_DEPTH, &commitments);
        // Pre-compute the resource nullifiers
        for (current_pos, resource) in &state.note_map {
            for fvk in fvks {
                if resource.resource.nk_commitment == fvk.nullifier_key.commit().0 {
                    let nullifier_key = NullifierKey { bytes: fvk.nullifier_key.0 };
                    let nullifier = resource.resource.nullifier(nullifier_key);
                    state.nf_map.insert(nullifier, *current_pos);
                    state.pos_map.entry(fvk.clone()).or_default().insert(*current_pos);
                    break;
                }
            }
        }
        // Scan the nullifiers in the queue
        for nullifier in pool.nullifiers {
            if let Some(pos) = state.nf_map.get(&nullifier) {
                state.spent_notes.insert(*pos);
            }
        }
        state
    }
}
