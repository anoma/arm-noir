use std::option::Option;
use std::static_assert;
use std::hash::pedersen_commitment;
use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use bigcurve::{Secp256k1, BigCurve, Secp256k1Scalar};

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
pub global MAX_CONSUMED: u32 = 4;
global NONCE_DERIVATION_PERSONALIZATION_LEN: u32 = 20;
global NONCE_DERIVATION_PERSONALIZATION: [u8; NONCE_DERIVATION_PERSONALIZATION_LEN] = "ARM_NONCE_DERIVATION".as_bytes();
global NONCE_INDEX_BYTES: u32 = 4;
global NONCE_PREIMAGE_LEN: u32 = NONCE_DERIVATION_PERSONALIZATION_LEN + NONCE_INDEX_BYTES + DIGEST_BYTES;

/// Nullifier key
pub struct NullifierKey {
    pub bytes: [u8; DIGEST_BYTES],
}

impl NullifierKey {
    /// Compute the commitment to the nullifier key
    pub fn commit(self) -> [u8; DIGEST_BYTES] {
        keccak256::keccak256(self.bytes, DIGEST_BYTES)
    }
}

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

/// Write the source array into the destination array at the given offset
pub fn write_bytes<let N: u32, let M: u32>(dest: &mut [u8; N], offset: &mut u32, src: [u8; M]) {
    // Copy the bytes
    for i in 0..M {
        dest[*offset + i] = src[i];
    }
    // Update the offset
    *offset += M;
}

impl Resource {
    /// Convert the quantity to a field element
    pub fn quantity_scalar(self) -> Field {
        self.quantity as Field
    }
    
    /// Compute the inner psi for the resource
    pub fn psi(self) -> [u8; DIGEST_BYTES] {
        let mut bytes = [0u8; PSI_BYTES];
        let mut offset: u32 = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        write_bytes(&mut bytes, &mut offset, PRF_EXPAND_PERSONALIZATION);
        // Write the PRF_EXPAND_PSI
        write_bytes(&mut bytes, &mut offset, [PRF_EXPAND_PSI]);
        // Write the random seed
        write_bytes(&mut bytes, &mut offset, self.rand_seed);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, self.nonce);
        static_assert(offset == PSI_BYTES, "resource psi pre-image malformed");
        keccak256::keccak256(bytes, PSI_BYTES)
    }

    /// Compute the randomness to commit the resource
    pub fn rcm(self) -> [u8; DIGEST_BYTES]  {
        let mut bytes = [0u8; RCM_BYTES];
        let mut offset: u32 = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        write_bytes(&mut bytes, &mut offset, PRF_EXPAND_PERSONALIZATION);
        // Write the PRF_EXPAND_RCM
        write_bytes(&mut bytes, &mut offset, [PRF_EXPAND_RCM]);
        // Write the random seed
        write_bytes(&mut bytes, &mut offset, self.rand_seed);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, self.nonce);
        static_assert(offset == RCM_BYTES, "resource rcm pre-image malformed");
        keccak256::keccak256(bytes, RCM_BYTES)
    }
    
    fn to_bytes(self) -> [u8; RESOURCE_BYTES] {
        // Concatenate all the components of this resource
        let mut bytes = [0; RESOURCE_BYTES];
        let mut offset: u32 = 0;
        // Write the image ID bytes
        write_bytes(&mut bytes, &mut offset, self.logic_ref);
        // Write the label_ref bytes
        write_bytes(&mut bytes, &mut offset, self.label_ref);
        // Write the fungible value_ref bytes
        write_bytes(&mut bytes, &mut offset, self.value_ref);
        // Write the quantity bytes
        let q_bytes = (self.quantity as Field).to_be_bytes::<QUANTITY_BYTES>();
        write_bytes(&mut bytes, &mut offset, q_bytes);
        // Write the nonce bytes
        write_bytes(&mut bytes, &mut offset, self.nonce);
        // Write the nullifier public key bytes
        write_bytes(&mut bytes, &mut offset, self.nk_commitment);
        // Write the randomness seed bytes
        let rcm = self.rcm();
        write_bytes(&mut bytes, &mut offset, rcm);
        // Write the ephemeral flag
        write_bytes(&mut bytes, &mut offset, [self.is_ephemeral as u8]);
        static_assert(offset == RESOURCE_BYTES, "resource commitment pre-image malformed");
        bytes
    }

    /// Compute the commitment to the resource
    pub fn commitment(self) -> [u8; DIGEST_BYTES] {
        // Now produce the hash
        keccak256::keccak256(self.to_bytes(), RESOURCE_BYTES)
    }

    /// Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: NullifierKey) -> [u8; DIGEST_BYTES] {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, cm)
    }

    /// Compute the nullifier of the resource from its commitment
    pub fn nullifier_from_commitment(self, nk: NullifierKey, cm: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        // Make sure that the nullifier public key corresponds to the secret key
        assert(self.nk_commitment == nk.commit());
        let mut bytes = [0u8; 4 * DIGEST_BYTES];
        let mut offset: u32 = 0;
        // Write the resource commitment
        write_bytes(&mut bytes, &mut offset, cm);
        // Write the nullifier secret key
        write_bytes(&mut bytes, &mut offset, nk.bytes);
        // Write the nonce
        write_bytes(&mut bytes, &mut offset, self.nonce);
        // Write psi
        let psi = self.psi();
        write_bytes(&mut bytes, &mut offset, psi);
        static_assert(offset == 4 * DIGEST_BYTES, "nullifier pre-image malformed");
        keccak256::keccak256(bytes, offset)
    }

    /// Compute the kind of the resource
    pub fn kind(self) -> EmbeddedCurvePoint {
        // Concatenate the logic_ref and label_ref
        let logic_ref = Field::from_le_bytes(self.logic_ref);
        let label_ref = Field::from_le_bytes(self.label_ref);
        // Hash to a curve point
        pedersen_commitment([logic_ref, label_ref])
    }

    /// Compute the secp256k1 kind of the resource
    pub fn kind_secp256k1(self) -> Secp256k1 {
        // Concatenate the logic_ref and label_ref
        let mut kind_preimage = [0u8; 2*DIGEST_BYTES];
        let mut offset = 0;
        write_bytes(&mut kind_preimage, &mut offset, self.logic_ref);
        write_bytes(&mut kind_preimage, &mut offset, self.label_ref);
        // Hash to a curve point
        Secp256k1::hash_to_curve(kind_preimage)
    }

    /// Derives the nonce by hashing
    /// `ARM_NONCE_DERIVATION || index_be || nullifiers_digest`.
    pub fn derive_nonce(index: u32, nullifiers_digest: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        let mut bytes = [0u8; NONCE_PREIMAGE_LEN];
        let mut offset: u32 = 0;
        write_bytes(&mut bytes, &mut offset, NONCE_DERIVATION_PERSONALIZATION);
        write_bytes(&mut bytes, &mut offset, (index as Field).to_be_bytes::<NONCE_INDEX_BYTES>());
        write_bytes(&mut bytes, &mut offset, nullifiers_digest);
        static_assert(offset == NONCE_PREIMAGE_LEN, "nonce pre-image malformed");
        sha256::sha256_var(bytes, offset)
    }

    /// Hashes the concatenation of the passed nullifier digests.
    /// Fails if `nullifiers` is empty.
    pub fn hash_nullifiers(nullifiers: [[u8; DIGEST_BYTES]; MAX_CONSUMED], count: u32) -> [u8; DIGEST_BYTES] {
        assert(count > 0);
        assert(count <= MAX_CONSUMED);
        let mut hash_input = [0u8; MAX_CONSUMED * DIGEST_BYTES];
        let mut offset: u32 = 0;
        for i in 0..MAX_CONSUMED {
            if i < count {
                write_bytes(&mut hash_input, &mut offset, nullifiers[i]);
            }
        }
        assert(offset == count * DIGEST_BYTES, "nullifier concatenation malformed");
        sha256::sha256_var(hash_input, offset)
    }
}
