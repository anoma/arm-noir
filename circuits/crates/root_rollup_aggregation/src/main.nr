use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use schnorr::verify_signature;
use bb_proof_verification::{RollupHonkProof, RollupHonkVerificationKey, verify_root_rolluphonk_proof};
use core::write_bytes;
use std::static_assert;
global FIELD_BYTES: u32 = 32;

// --- Main Entry Point ---
fn main(
    verification_key: [RollupHonkVerificationKey; 2],
    proofs: [RollupHonkProof; 2],
    public_inputs: [Field; 2],
    key_hash: [Field; 2],
) -> pub Field {
    verify_root_rolluphonk_proof(verification_key[0], proofs[0], [public_inputs[0]], key_hash[0]);
    verify_root_rolluphonk_proof(verification_key[1], proofs[1], [public_inputs[1]], key_hash[1]);
    let mut buf = [0; FIELD_BYTES*4];
    let mut buf_len = 0;
    write_bytes(&mut buf, &mut buf_len, key_hash[0].to_le_bytes::<FIELD_BYTES>());
    write_bytes(&mut buf, &mut buf_len, key_hash[1].to_le_bytes::<FIELD_BYTES>());
    write_bytes(&mut buf, &mut buf_len, public_inputs[0].to_le_bytes::<FIELD_BYTES>());
    write_bytes(&mut buf, &mut buf_len, public_inputs[1].to_le_bytes::<FIELD_BYTES>());
    static_assert(buf_len == FIELD_BYTES*4, "node hash pre-image malformed");
    Field::from_le_bytes(keccak256::keccak256(buf, buf_len))
}
