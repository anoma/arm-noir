use core::{MAX_CONSUMED, write_bytes, NullifierKey, Resource};
use bigcurve::{Secp256k1, BigCurve, Secp256k1Scalar};

// --- Circuit Globals ---
global DIGEST_BYTES: u32 = 32;
global MAX_CREATED: u32 = 4;
global MAX_KINDS: u32 = 8;
global MAX_KIND_TABLE: u32 = 10;

// --- Compliance Structs ---
struct MerklePath {
    path: [[u8; DIGEST_BYTES]; 32], // Assuming tree depth 32
}

struct ConsumedResourceWitness {
    resource: Resource,
    cm_merkle_path: MerklePath,
    nf_key: NullifierKey,
}

struct ConsumedResourcePublic {
    resource_nullifier: [u8; DIGEST_BYTES],
    resource_logic_ref: [u8; DIGEST_BYTES],
    commitment_tree_root: [u8; DIGEST_BYTES],
}

struct CreatedResourcePublic {
    resource_commitment: [u8; DIGEST_BYTES],
    resource_logic_ref: [u8; DIGEST_BYTES],
}

struct KindTableEntry {
    logic_ref: [u8; DIGEST_BYTES],
    label_ref: [u8; DIGEST_BYTES],
    kind_point: Secp256k1, // Handled directly as point to avoid runtime decoding
}

struct ComplianceInstance {
    consumed_publics: [ConsumedResourcePublic; MAX_CONSUMED],
    consumed_count: u32,
    created_publics: [CreatedResourcePublic; MAX_CREATED],
    created_count: u32,
    delta: Secp256k1,
    kind_table_commitment: [u8; DIGEST_BYTES],
}

struct ComplianceWitness {
    consumed_data: [ConsumedResourceWitness; MAX_CONSUMED],
    consumed_count: u32,
    created_resources: [Resource; MAX_CREATED],
    created_count: u32,
    ephemeral_root: [u8; DIGEST_BYTES],
    rcv: Secp256k1Scalar, // Scalar parsed to field
    kind_table: [KindTableEntry; MAX_KIND_TABLE],
    kind_table_count: u32,
}

impl ComplianceWitness {
    fn _constrain(self) -> ComplianceInstance {
        let mut consumed_nullifiers = [[0; DIGEST_BYTES]; MAX_CONSUMED];
        let mut consumed_publics = [ConsumedResourcePublic {
            resource_nullifier: [0; 32], resource_logic_ref: [0; 32], commitment_tree_root: [0; 32]
        }; MAX_CONSUMED];
        
        let mut kinds = [Secp256k1::point_at_infinity(); MAX_KINDS];
        let mut sums = [0 as Field; MAX_KINDS];
        let mut kind_count: u32 = 0;

        // Process consumed resources
        for i in 0..MAX_CONSUMED {
            if i < self.consumed_count {
                let w = self.consumed_data[i];
                let resource_nullifier = w.resource.nullify(w.nf_key);
                
                let root = if w.resource.is_ephemeral {
                    self.ephemeral_root
                } else {
                    [0; DIGEST_BYTES] // Merkle path root calculation stub
                };

                consumed_publics[i] = ConsumedResourcePublic {
                    resource_nullifier,
                    resource_logic_ref: w.resource.logic_ref,
                    commitment_tree_root: root,
                };
                consumed_nullifiers[i] = resource_nullifier;
                accumulate_kind(
                    &mut kinds,
                    &mut sums,
                    &mut kind_count,
                    self.lookup_kind(w.resource),
                    w.resource.quantity_scalar(),
                );
            }
        }

        // Process created resources
        let consumed_nullifiers_digest = Resource::hash_nullifiers(consumed_nullifiers, self.consumed_count);
        let mut created_publics = [CreatedResourcePublic {
            resource_commitment: [0; 32], resource_logic_ref: [0; 32]
        }; MAX_CREATED];

        for i in 0..MAX_CREATED {
            if i < self.created_count {
                let resource = self.created_resources[i];
                let derived_nonce = Resource::derive_nonce(i as u32, consumed_nullifiers_digest);
                assert(derived_nonce == resource.nonce);

                created_publics[i] = CreatedResourcePublic {
                    resource_commitment: resource.commitment(),
                    resource_logic_ref: resource.logic_ref,
                };
                accumulate_kind(
                    &mut kinds,
                    &mut sums,
                    &mut kind_count,
                    self.lookup_kind(resource),
                    -resource.quantity_scalar(),
                );
            }
        }

        // Calculate Pedersen commitment delta
        let mut delta = Secp256k1::point_at_infinity();
        for i in 0..MAX_KINDS {
            if i < kind_count {
                delta += kinds[i].mul(Secp256k1Scalar::from(sums[i]));
            }
        }
        delta = delta + Secp256k1::one().mul(self.rcv);

        let kind_table_commitment = [0; DIGEST_BYTES]; // Hash table stub

        ComplianceInstance {
            consumed_publics,
            consumed_count: self.consumed_count,
            created_publics,
            created_count: self.created_count,
            delta: delta, // Encode stub
            kind_table_commitment,
        }
    }

    fn lookup_kind(self, _resource: Resource) -> Secp256k1 {
        // Stub: iterates over self.kind_table up to kind_table_count
        Secp256k1::point_at_infinity()
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
    kinds: &mut [Secp256k1; MAX_KINDS],
    sums: &mut [Field; MAX_KINDS],
    kind_count: &mut u32,
    kind_point: Secp256k1,
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
        kinds[*kind_count] = kind_point;
        sums[*kind_count] = signed_quantity;
        *kind_count += 1;
    }
}

// --- Main Entry Point ---
fn main(witness: ComplianceWitness) -> pub ComplianceInstance {
    witness._constrain()
}
