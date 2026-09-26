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
use crate::pad_slice;

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
