use core::{MAX_CONSUMED, write_bytes, NullifierKey, Resource};
use bigcurve::{Secp256k1, BigCurve, Secp256k1Scalar};
use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};
use poseidon::poseidon2;

// --- Circuit Globals ---
global DIGEST_BYTES: u32 = 32;
global MAX_CREATED: u32 = 4;
global MAX_KINDS: u32 = 8;
global MAX_TREE_DEPTH: u32 = 32; // Set this to your actual max commitment tree depth

/// A constant padding leaf used in Merkle trees.
/// This is the hash of an empty string.
global PADDING_LEAF: [u8; DIGEST_BYTES] = [
    0xcc, 0x1d, 0x2f, 0x83, 0x84, 0x45, 0xdb, 0x7a,
    0xec, 0x43, 0x1d, 0xf9, 0xee, 0x8a, 0x87, 0x1f,
    0x40, 0xe7, 0xaa, 0x5e, 0x06, 0x4f, 0xc0, 0x56,
    0x63, 0x3e, 0xf8, 0xc6, 0x0f, 0xab, 0x7b, 0x06
];

// --- Cryptographic Utilities ---

/// A path from a position in a particular commitment tree to the root of that tree.
struct MerklePath {
    path: [(Field, bool); MAX_TREE_DEPTH],
    depth: u32, // Logical length of the path (since the array is statically sized)
}

impl MerklePath {
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    fn root(self, leaf: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        let mut current_root = Field::from_le_bytes(leaf);
        for i in 0..MAX_TREE_DEPTH {
            if i < self.depth {
                let (sibling, leaf_is_on_right) = self.path[i];
                current_root = if leaf_is_on_right {
                    poseidon2::Poseidon2::hash([sibling, current_root], 2)
                } else {
                    poseidon2::Poseidon2::hash([current_root, sibling], 2)
                };
            }
        }
        current_root.to_le_bytes()
    }

    /// Returns the logical length of the Merkle path.
    fn len(self) -> u32 {
        self.depth
    }

    /// Checks if the Merkle path is empty.
    fn is_empty(self) -> bool {
        self.depth == 0
    }

    /// Creates an empty Merkle path.
    fn empty() -> Self {
        MerklePath {
            path: [(0, false); MAX_TREE_DEPTH],
            depth: 0,
        }
    }
}

/// Private information related to a consumed resource.
struct ConsumedResourceWitness {
    /// The consumed resource.
    resource: Resource,
    /// The path from the consumed commitment to the root of the commitment tree.
    cm_merkle_path: MerklePath,
    /// Nullifier key of the consumed resource.
    nf_key: NullifierKey,
}

/// Public information of consumed resources.
struct ConsumedResourcePublic {
    /// The nullifier of the consumed [Resource].
    resource_nullifier: [u8; DIGEST_BYTES],
    /// The logic reference of the consumed [Resource].
    resource_logic_ref: [u8; DIGEST_BYTES],
    /// The root of the Merkle tree where the resource commitment is in.
    commitment_tree_root: [u8; DIGEST_BYTES],
}

/// Public information of created resources.
struct CreatedResourcePublic {
    /// The commitment to the created [Resource].
    resource_commitment: [u8; DIGEST_BYTES],
    /// The logic reference of the created [Resource].
    resource_logic_ref: [u8; DIGEST_BYTES],
}

/// The compliance instance contains all public inputs to the compliance proof.
struct ComplianceInstance {
    /// Public information of consumed resources
    consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    consumed_count: u32,
    /// Public information of created resources
    created_publics: [CreatedResourcePublic; MAX_CREATED],
    created_count: u32,
    /// The delta coordinates of the created resource
    delta: EmbeddedCurvePoint,
}

/// The compliance witness contains all private inputs to the compliance proof.
struct ComplianceWitness {
    /// Private information of consumed resources
    consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    consumed_count: u32,
    /// Private information of created resources
    created_resources: [Resource; MAX_CREATED],
    created_count: u32,
    /// The existing root for ephemeral resources
    ephemeral_root: [u8; DIGEST_BYTES],
    /// Bytes of randomness for the delta commitment `rcv`
    rcv: EmbeddedCurveScalar, // Scalar parsed to field
}

impl ComplianceWitness {
    /// Compliance constraints. Produces the public outputs of the unit by
    /// re-computing nullifiers, commitments, tree roots, and the delta
    /// commitment from the witness data.
    ///
    /// Each input resource is touched in a single pass: the same loop over
    /// `consumed_data` (and over `created_resources`) builds the public outputs
    /// and accumulates the (kind, signed-quantity) contributions used for the
    /// delta commitment, so each `commitment()`, `kind()`, and field load
    /// happens once.
    fn _constrain(self) -> ComplianceInstance {
        let mut consumed_nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
        let mut consumed_publics = [ConsumedResourcePublic {
            resource_nullifier: [0; 32],
            resource_logic_ref: [0; 32],
            commitment_tree_root: [0; 32]
        }; MAX_CONSUMED];
        
        let mut kinds = [EmbeddedCurvePoint::point_at_infinity(); MAX_KINDS];
        let mut sums = [(false, 0); MAX_KINDS];
        let mut kind_count: u32 = 0;

        // Constrain consumed resources and accumulate their (kind, +quantity)
        // contributions to the delta.
        for i in 0..MAX_CONSUMED {
            if i < self.consumed_count {
                let w = self.consumed_data[i];
                let resource_commitment = w.resource.commitment();
                let resource_nullifier = w
                    .resource
                    .nullifier_from_commitment(w.nf_key, resource_commitment);
                
                let commitment_tree_root = if w.resource.is_ephemeral {
                    self.ephemeral_root
                } else {
                    w.cm_merkle_path.root(resource_commitment)
                };

                consumed_publics[i] = ConsumedResourcePublic {
                    resource_nullifier,
                    resource_logic_ref: w.resource.logic_ref,
                    commitment_tree_root: commitment_tree_root,
                };
                consumed_nullifiers[i] = resource_nullifier;
                accumulate_kind(
                    &mut kinds,
                    &mut sums,
                    &mut kind_count,
                    w.resource.kind(),
                    (false, w.resource.quantity),
                );
            }
        }

        // Constrain created resources: re-derive each nonce from the consumed
        // nullifiers, require it to match, and accumulate (kind, -quantity).
        let consumed_nullifiers_digest = Resource::hash_nullifiers(consumed_nullifiers, self.consumed_count);
        let mut created_publics = [CreatedResourcePublic {
            resource_commitment: [0; 32],
            resource_logic_ref: [0; 32]
        }; MAX_CREATED];

        for index in 0..MAX_CREATED {
            if index < self.created_count {
                let resource = self.created_resources[index];
                let derived_nonce = Resource::derive_nonce(index as u32, consumed_nullifiers_digest);
                assert(derived_nonce == resource.nonce);

                created_publics[index] = CreatedResourcePublic {
                    resource_commitment: resource.commitment(),
                    resource_logic_ref: resource.logic_ref,
                };
                accumulate_kind(
                    &mut kinds,
                    &mut sums,
                    &mut kind_count,
                    resource.kind(),
                    (true, resource.quantity),
                );
            }
        }

        // Convert the magnitudes into scalars and move the sign into the kind
        let sum_scalars = sums.map(|(_neg, mag)| EmbeddedCurveScalar::from_field(mag as Field));
        for k in 0..MAX_KINDS {
            // If the current magnitude is negative
            if sums[k].0 {
                // Then negate the kind instead of the scalar
                kinds[k] = -kinds[k];
            }
        }
        // Pedersen commit to the per-kind sums; the binding generators are the
        // kind points themselves, plus the standard generator for `rcv`.
        let delta = multi_scalar_mul(kinds, sum_scalars) + fixed_base_scalar_mul(self.rcv);

        ComplianceInstance {
            consumed_publics,
            consumed_count: self.consumed_count,
            created_publics,
            created_count: self.created_count,
            delta: delta,
        }
    }
}

/// Takes two numbers in sign-magnitude form and adds them together. The
/// boolean being true indicates that the number is negative.
fn add_sign_magnitude(a: (bool, u128), b: (bool, u128)) -> (bool, u128) {
    if a.0 == b.0 {
        (a.0, a.1 + b.1)
    } else if a.1 >= b.1 {
        (a.0, a.1 - b.1)
    } else {
        (b.0, b.1 - a.1)
    }
}

/// Adds `signed_quantity` to the running sum for `kind`, inserting a new
/// (kind, sum) pair when the kind is seen for the first time.
///
/// The lookup is a linear scan, so this is O(N²) in the number of distinct
/// kinds. That is intentional: in a circuit, a scalar multiplication is far
/// more expensive than a curve-point equality, so trading per-resource scalar
/// mults for a few extra comparisons is the right side of the trade-off for
/// the unit sizes we expect.
fn accumulate_kind(
    kinds: &mut [EmbeddedCurvePoint; MAX_KINDS],
    sums: &mut [(bool, u128); MAX_KINDS],
    kind_count: &mut u32,
    kind_point: EmbeddedCurvePoint,
    signed_quantity: (bool, u128),
) {
    let mut found = false;
    for k in 0..MAX_KINDS {
        if (k < *kind_count) & (kinds[k] == kind_point) {
            sums[k] = add_sign_magnitude(sums[k], signed_quantity);
            found = true;
        }
    }
    if found == false {
        assert(*kind_count < MAX_KINDS, "Exceeded maximum unique resource kinds");
        kinds[*kind_count] = kind_point;
        sums[*kind_count] = signed_quantity;
        *kind_count += 1;
    }
}

// --- Main Entry Point ---
fn main(witness: ComplianceWitness) -> pub ComplianceInstance {
    witness._constrain()
}

#[test]
fn test_compliance_valid() {
    // 1. Setup the Nullifier Key
    let nk_bytes: [u8; DIGEST_BYTES] = [1; DIGEST_BYTES];
    let nk = NullifierKey { bytes: nk_bytes };
    let nk_comm = nk.commit();

    // 2. Setup a valid Consumed Resource
    let consumed_res = Resource {
        logic_ref: [2; DIGEST_BYTES],
        label_ref: [3; DIGEST_BYTES],
        value_ref: [4; DIGEST_BYTES],
        quantity: 100,
        nonce: [5; DIGEST_BYTES],
        nk_commitment: nk_comm, // Must match nk.commit()
        is_ephemeral: false,
        rand_seed: [6; DIGEST_BYTES],
    };

    let consumed_comm = consumed_res.commitment();
    let consumed_nullifier = consumed_res.nullifier_from_commitment(nk, consumed_comm);

    // 3. Setup the Consumed Resource Witness using an empty Merkle Path
    let consumed_data = ConsumedResourceWitness {
        resource: consumed_res,
        cm_merkle_path: MerklePath::empty(),
        nf_key: nk,
    };

    // 4. Pre-compute the expected nonce for the Created Resource
    // The circuit derives the created resource's nonce from the hash of the consumed nullifiers.
    let mut nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
    nullifiers[0] = consumed_nullifier;
    let nullifiers_digest = Resource::hash_nullifiers(nullifiers, 1);
    
    // We are creating this as the 0-th created resource, so index = 0
    let derived_nonce = Resource::derive_nonce(0, nullifiers_digest);

    // 5. Setup the Created Resource
    let created_res = Resource {
        logic_ref: [2; DIGEST_BYTES], // Keep the same kind to test quantity accumulation
        label_ref: [3; DIGEST_BYTES],
        value_ref: [4; DIGEST_BYTES],
        quantity: 100,                // Consumed 100, created 100 (balances out)
        nonce: derived_nonce,         // MUST match the derived nonce to pass constraints
        nk_commitment: nk_comm,
        is_ephemeral: false,
        rand_seed: [7; DIGEST_BYTES],
    };

    // 6. Pad arrays to match global limits (MAX_CONSUMED / MAX_CREATED)
    let consumed_arr = [consumed_data; MAX_CONSUMED];
    let created_arr = [created_res; MAX_CREATED];

    // 7. Assemble the full Compliance Witness
    let witness = ComplianceWitness {
        consumed_data: consumed_arr,
        consumed_count: 1,
        created_resources: created_arr,
        created_count: 1,
        ephemeral_root: [0; DIGEST_BYTES],
        // Using a zero scalar for the delta commitment randomness to keep the test simple
        rcv: EmbeddedCurveScalar::from_field(0), 
    };

    // 8. Execute the main constraint logic
    let instance = main(witness);

    // 9. Verify the resulting public instance matches expectations
    assert(instance.consumed_count == 1);
    assert(instance.created_count == 1);
    
    // Verify the outputted nullifier and commitment match our pre-computed ones
    assert(instance.consumed_publics[0].resource_nullifier == consumed_nullifier);
    assert(instance.created_publics[0].resource_commitment == created_res.commitment());
}
