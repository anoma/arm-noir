use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use schnorr::verify_signature;
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use core::write_bytes;
use std::static_assert;
global FIELD_BYTES: u32 = 32;

// --- Main Entry Point ---
fn main(
    verification_key: [UltraHonkVerificationKey; 10],
    proof: [UltraHonkProof; 10],
    public_inputs: [Field; 10],
    key_hash: [Field; 10],
) {
    for i in 0..10 {
        verify_honk_proof_non_zk(verification_key[i], proof[i], [public_inputs[i]], key_hash[i]);
    }
}

