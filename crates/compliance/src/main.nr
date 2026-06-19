use core::{MAX_CONSUMED, write_bytes, NullifierKey, Resource};
use bigcurve::{Secp256k1, BigCurve, Secp256k1Scalar};
use std::embedded_curve_ops::{fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar};

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

/// Hashes two digests together using SHA-256.
fn hash_two(
    left: [u8; DIGEST_BYTES],
    right: [u8; DIGEST_BYTES],
) -> [u8; DIGEST_BYTES] {
    let mut hash_input = [0; 64]; // DIGEST_BYTES * 2
    let mut offset = 0u32;
    write_bytes(&mut hash_input, &mut offset, left);
    write_bytes(&mut hash_input, &mut offset, right);
    sha256::digest(hash_input)
}

/// A path from a position in a particular commitment tree to the root of that tree.
struct MerklePath {
    path: [([u8; DIGEST_BYTES], bool); MAX_TREE_DEPTH],
    depth: u32, // Logical length of the path (since the array is statically sized)
}

impl MerklePath {
    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    fn root(self, leaf: [u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
        let mut current_root = leaf;
        for i in 0..MAX_TREE_DEPTH {
            if i < self.depth {
                let (sibling, leaf_is_on_right) = self.path[i];
                current_root = if leaf_is_on_right {
                    hash_two(current_root, sibling)
                } else {
                    hash_two(sibling, current_root)
                };
            }
        }
        current_root
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
            path: [([0; DIGEST_BYTES], false); MAX_TREE_DEPTH],
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
    fn _constrain(self) -> ComplianceInstance {
        let mut consumed_nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
        let mut consumed_publics = [ConsumedResourcePublic {
            resource_nullifier: [0; 32], resource_logic_ref: [0; 32], commitment_tree_root: [0; 32]
        }; MAX_CONSUMED];
        
        let mut kinds = [EmbeddedCurvePoint::point_at_infinity(); MAX_KINDS];
        let mut sums = [0 as Field; MAX_KINDS];
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
                    w.resource.quantity_scalar(),
                );
            }
        }

        // Constrain created resources: re-derive each nonce from the consumed
        // nullifiers, require it to match, and accumulate (kind, -quantity).
        let consumed_nullifiers_digest = Resource::hash_nullifiers(consumed_nullifiers, self.consumed_count);
        let mut created_publics = [CreatedResourcePublic {
            resource_commitment: [0; 32], resource_logic_ref: [0; 32]
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
                    -resource.quantity_scalar(),
                );
            }
        }

        // Pedersen commit to the per-kind sums; the binding generators are the
        // kind points themselves, plus the standard generator for `rcv`.
        let mut sum_scalars = sums.map(EmbeddedCurveScalar::from_field);
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
    sums: &mut [Field; MAX_KINDS],
    kind_count: &mut u32,
    kind_point: EmbeddedCurvePoint,
    signed_quantity: Field,
) {
    let mut found = false;
    for k in 0..MAX_KINDS {
        if (k < *kind_count) & (kinds[k] == kind_point) {
            sums[k] = sums[k] + signed_quantity;
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
