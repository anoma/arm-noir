use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use schnorr::verify_signature;

// --- Main Entry Point ---
fn main(
    public_key: pub EmbeddedCurvePoint,
    signature: pub (EmbeddedCurveScalar, EmbeddedCurveScalar),
    message: pub Field,
) {
    assert(verify_signature(public_key, signature, message));
}

#[test(should_fail)]
fn zero_signature() {
    let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint::generator();
    let signature: (EmbeddedCurveScalar, EmbeddedCurveScalar) =
        (EmbeddedCurveScalar::new(0, 0), EmbeddedCurveScalar::new(0, 0));
    let message: Field = 0x1234;
    main(public_key, signature, message);
}

#[test]
fn pinned_vector_small() {
    let public_key = EmbeddedCurvePoint::new(
        0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f,
        0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c,
    );
    let sig_s = EmbeddedCurveScalar::new(
        0x5fd1ac0ad411110674830c54cb506212,
        0x281906862cdb4e0efec7226d757fe803,
    );
    let sig_e = EmbeddedCurveScalar::new(
        0x6c368959f958e525d761d06c47fd2ad6,
        0x013f6a902c6c0efafdadbd4de409690d,
    );
    let message: Field = 0x2bc;
    main(public_key, (sig_s, sig_e), message);
}

#[test]
fn pinned_vector_large() {
    let public_key = EmbeddedCurvePoint::new(
        0x065812e335a97c2108ea8cf4ccfe2f9dd6b117a0714f5e18461575be93f61da6,
        0x1a915003e8ec534f9a15d926a7ded478e178468ccc4f28e236e67450a55ac622,
    );
    let sig_s = EmbeddedCurveScalar::new(
        0xf3bc3b7147acb9c621fd9f72dbf15ffa,
        0x08599f379f0301dfefdbd0272554454d,
    );
    let sig_e = EmbeddedCurveScalar::new(
        0x97065383ebbbd76620398792bd259bc2,
        0x2ceaee87f45b7a417f0ffb05451a8c92,
    );
    let message: Field = 0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321;
    main(public_key, (sig_s, sig_e), message);
}
