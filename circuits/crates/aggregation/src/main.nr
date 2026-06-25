use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use schnorr::verify_signature;
use bb_proof_verification::{UltraHonkZKProof, UltraHonkVerificationKey, verify_honk_proof};

// --- Main Entry Point ---
fn main(
    verification_key: UltraHonkVerificationKey,
    proof: UltraHonkZKProof,
    public_inputs: pub [Field; 1],
    key_hash: pub Field,
) {
    verify_honk_proof(verification_key, proof, public_inputs, key_hash);
}
