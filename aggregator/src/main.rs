use std::collections::VecDeque;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::fmt::Display;
use sha2::{Sha256, Digest};
use std::ops::RangeFrom;
use std::path::PathBuf;
use barretenberg_rs::generated_types::CircuitProveResponse;
use proptest::prelude::*;
use nargo::ops::execute_program;
use noir_artifact_cli::Artifact;
use noirc_artifacts::program::CompiledProgram;
use nargo::foreign_calls::{layers, DefaultForeignCallBuilder};
use noir_artifact_cli::execution;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use nargo::foreign_calls::transcript::ReplayForeignCallExecutor;
use acir::circuit::Program;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::generated_types::{CircuitInput, CircuitInputNoVK};
use barretenberg_rs::generated_types::ProofSystemSettings;
use acir::SerializationFormat;
use std::io::Read;

const CRS_DIR: &str = ".bb-crs";
const G1_UNCOMPRESSED_DATA_PATH: &str = "bn254_g1.dat";
const G2_UNCOMPRESSED_DATA_PATH: &str = "bn254_g2.dat";

/// Type alias to ease generic usage of aggregators
type AggregatorBox<A> = Box<dyn Aggregator<AggregatorId = <A as Aggregator>::AggregatorId, Proof = <A as Aggregator>::Proof, BatchId = <A as Aggregator>::BatchId>>;

/// The interface shared by all proof aggregators
pub trait Aggregator {
    /// The type that holds aggregator IDs
    type AggregatorId;
    /// The type that holds batch IDs
    type BatchId;
    /// The type that holds proofs
    type Proof;
    /// Push a batch of proofs to aggregate onto a queue
    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>) -> Self::BatchId;
    /// Pop a recursive proof from the queue of aggregations
    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Proof)>;
    /// Get the number of remaining aggregations to do
    fn pending_queue_size(&self) -> usize;
    /// Get the rate at which proofs are aggregated in a unit of time. Return value must be >= 1.
    fn proof_throughput(&self) -> f64;
    /// Add a sub-aggregator that will help in aggregating proofs
    fn insert_sub_aggregator(&mut self, sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId;
    /// Remove the given sub-aggregator from the set of helpers
    fn remove_sub_aggregator(&mut self, id: &Self::AggregatorId) -> Option<AggregatorBox<Self>>;
    /// Consume leaf and internal proofs and produce aggregate proofs
    fn step(&mut self);
}

/// Generate an ID from an essentially infinite iterator
fn gen_id<I: Iterator>(i: &mut I) -> I::Item {
    i.next().expect("Exhausted free IDs")
}

/// Data structure that primarily prioritizes aggregators with lower expected wait times.
/// Secondarily it prioritizes aggregators with high throughputs. This is to reduce the
/// fragmentation of batches.
#[derive(PartialEq, PartialOrd)]
struct AggregatorLoad<AggregatorId> {
    /// How long do we expect to wait before the current load completes?
    pub expected_wait_time: f64,
    /// How many proofs are processed per unit of time? Negate this value.
    pub negative_throughput: f64,
    /// The ID of the aggregator that these statistics pertain to.
    pub aggregator_id: AggregatorId,
}

impl<AggregatorId> AggregatorLoad<AggregatorId> {
    /// Comput load statistics from the given aggregator
    pub fn new<A: Aggregator + ?Sized>(aggregator_id: AggregatorId, aggregator: &A) -> Self {
        let proof_throughput = aggregator.proof_throughput();
        let expected_wait_time = if proof_throughput == 0.0 {
            f64::INFINITY
        } else {
            aggregator.pending_queue_size() as f64 / proof_throughput
        };
        Self {
            expected_wait_time,
            negative_throughput: -proof_throughput,
            aggregator_id,
        }
    }
}

impl<AggregatorId: PartialEq> Eq for AggregatorLoad<AggregatorId> {}

impl<AggregatorId: PartialOrd> Ord for AggregatorLoad<AggregatorId> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("malformed AggregatorLoad object")
    }
}

/// Proof aggregator that works purely by delegating to workers
pub struct RecursiveAggregator<Proof, BatchIds: Iterator, AggregatorIds: Iterator> {
    /// The ID of this aggregator in its local namespace
    pub aggregator_id: AggregatorIds::Item,
    /// Queue of internal proofs to be aggregated
    pub internal_proofs: VecDeque<(BatchIds::Item, Vec<Proof>)>,
    /// Queue of produced recursive proofs
    pub recursive_proofs: VecDeque<(BatchIds::Item, Proof)>,
    /// Temporary place to store recursive proofs from sub-aggregators
    pub sub_recursive_proofs: HashMap<(AggregatorIds::Item, BatchIds::Item), Proof>,
    /// Proof aggregators to offload work onto
    pub sub_aggregators: HashMap<AggregatorIds::Item, Box<dyn Aggregator<AggregatorId = AggregatorIds::Item, BatchId = BatchIds::Item, Proof = Proof>>>,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: AggregatorIds,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// Map proofs to their parents
    pub proof_parents: HashMap<(AggregatorIds::Item, BatchIds::Item), (AggregatorIds::Item, BatchIds::Item)>,
    /// Map proofs to their children
    pub proof_children: HashMap<(AggregatorIds::Item, BatchIds::Item), ((AggregatorIds::Item, BatchIds::Item), (AggregatorIds::Item, BatchIds::Item))>,
    /// Map qualified batch IDs to their original batch IDs
    pub proof_aliases: HashMap<(AggregatorIds::Item, BatchIds::Item), BatchIds::Item>,
    /// Map qualified batch ID to vector of its leaf descendants
    pub proof_descendants: BTreeMap<(AggregatorIds::Item, BatchIds::Item), Vec<(AggregatorIds::Item, BatchIds::Item)>>,
}

impl<Proof, BatchIds: Iterator, AggregatorIds: Iterator> RecursiveAggregator<Proof, BatchIds, AggregatorIds> {
    pub fn new(free_batch_ids: BatchIds, mut free_aggregator_ids: AggregatorIds) -> Self {
        Self {
            aggregator_id: gen_id(&mut free_aggregator_ids),
            internal_proofs: VecDeque::new(),
            recursive_proofs: VecDeque::new(),
            sub_recursive_proofs: HashMap::new(),
            sub_aggregators: HashMap::new(),
            free_aggregator_ids,
            free_batch_ids,
            proof_parents: HashMap::new(),
            proof_children: HashMap::new(),
            proof_aliases: HashMap::new(),
            proof_descendants: BTreeMap::new(),
        }
    }
}

impl<AggregatorIds: Iterator, BatchIds: Iterator, Proof> Aggregator for RecursiveAggregator<Proof, BatchIds, AggregatorIds> where AggregatorIds::Item: Hash + Eq + Copy + Debug + PartialOrd + Ord + Display, BatchIds::Item: Hash + Eq + Copy + Ord + Debug {
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Proof = Proof;

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>) -> Self::BatchId {
        // Batch sizes must be powers of two
        assert!(proofs.len().is_power_of_two());
        // More than one proof must be supplied for there to be work to do
        assert!(proofs.len() > 1);
        let batch_id = gen_id(&mut self.free_batch_ids);
        self.internal_proofs.push_back((batch_id, proofs));
        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Proof)> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        // Get the proofs queued in this aggregator
        let local = self.internal_proofs.iter().map(|s| s.1.len()).sum::<usize>();
        // Get the proofs queued in the sub-aggregators
        let delegated: usize = self.sub_aggregators.values()
            .map(|agg| agg.pending_queue_size())
            .sum();
        // Return the total proofs queued
        local + delegated
    }

    fn proof_throughput(&self) -> f64 {
        // The throughput of a recursive aggregator is the sum of those of its sub-aggregators
        let throughput = self.sub_aggregators.values().map(|x| x.proof_throughput()).sum();
        throughput
    }

    fn insert_sub_aggregator(&mut self, sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId {
        // Save the sub-aggregator with the given free ID
        let aggregator_id = gen_id(&mut self.free_aggregator_ids);
        self.sub_aggregators.insert(aggregator_id, sub_aggregator);
        aggregator_id
    }

    fn remove_sub_aggregator(&mut self, id: &Self::AggregatorId) -> Option<AggregatorBox<Self>> {
        self.sub_aggregators.remove(id)
    }

    fn step(&mut self) {
        println!("Distribute ------------");
        // Compute the current aggregator loads
        let mut aggregator_ids: Vec<_> = self
            .sub_aggregators
            .iter()
            .map(|(id, agg)| AggregatorLoad::new(*id, &**agg))
            .collect();
        // Sort the aggregator IDs starting with the least loaded one first
        aggregator_ids.sort();
        // Get the total number of proofs that need to be distributed amongst aggregators
        let mut pending_queue_size = self.internal_proofs.iter().map(|s| s.1.len()).sum::<usize>();
        // While there are still pending proofs, distribute them amongst aggregators
        while pending_queue_size > 0 {
            // Indicates whether an appropriate aggregator to do the work has been found
            let mut aggregator_idx = None;
            // Now try to place some pending proofs at the least loaded aggregator that can be saturated
            for (idx, id) in aggregator_ids.iter().enumerate() {
                // Number of proofs required to saturate the aggregator
                let proof_throughput = self.sub_aggregators[&id.aggregator_id].proof_throughput() as usize * 2;
                // Only send the prefix of the queue if it can saturate this aggregator
                if proof_throughput == 0 || pending_queue_size < proof_throughput { continue; }
                // Indicate that an aggregator has been found
                aggregator_idx = Some(idx);
                let mut total_chunk_size = 0;
                // Take as many chunks as required to saturate the aggregator
                while total_chunk_size < proof_throughput {
                    // Compute the amount that needs to be drained to saturate the current aggregator
                    let (mut batch_id, mut batch) = self.internal_proofs.pop_front().unwrap();
                    let mut qualified_batch_id = (self.aggregator_id, batch_id);
                    let target_size = std::cmp::min(proof_throughput.next_power_of_two(), batch.len());
                    // Keep splitting off batches (that are powers of two) until we get to the correct size
                    while batch.len() > target_size {
                        // These remainder batches will be processed in future loops
                        let batch1_id = gen_id(&mut self.free_batch_ids);
                        let batch1 = batch.split_off(batch.len() / 2);
                        self.internal_proofs.push_front((batch1_id, batch1));
                        // Maintain a tree of proof dependencies
                        batch_id = gen_id(&mut self.free_batch_ids);
                        self.proof_parents.insert((self.aggregator_id, batch_id), qualified_batch_id);
                        self.proof_parents.insert((self.aggregator_id, batch1_id), qualified_batch_id);
                        self.proof_children.insert(qualified_batch_id, ((self.aggregator_id, batch_id), (self.aggregator_id, batch1_id)));
                        qualified_batch_id = (self.aggregator_id, batch_id);
                    }
                    // Add the drainage to the sub aggregator
                    total_chunk_size += batch.len();
                    println!("Sending {} proofs to aggregator {}", batch.len(), id.aggregator_id);
                    let new_batch_id = self.sub_aggregators.get_mut(&id.aggregator_id).unwrap().push_internal_proofs(batch);
                    let new_qualified_batch_id = (id.aggregator_id, new_batch_id);
                    // Replace the qualified batch ID with the new qualified batch ID
                    if let Some(parent) = self.proof_parents.remove(&qualified_batch_id) {
                        // Make the new qualified batch ID's parent the current one's parent
                        self.proof_parents.insert(new_qualified_batch_id, parent);
                        // And update the children of the parent to point to the new qualified batch ID
                        let children = self.proof_children.get_mut(&parent).unwrap();
                        if children.0 == qualified_batch_id {
                            children.0 = new_qualified_batch_id;
                        } else if children.1 == qualified_batch_id {
                            children.1 = new_qualified_batch_id;
                        }
                    } else {
                        // If there's no parent, then this is a root proof. So just alias it.
                        self.proof_aliases.insert(new_qualified_batch_id, batch_id);
                    }
                }
                // Sending the prefix will reduce this aggregator's queue size
                pending_queue_size -= total_chunk_size;
                break;
            }
            // Resort the aggregator loading vector since we've since loaded a sub-aggregator
            if let Some(idx) = aggregator_idx {
                // Get the aggregator ID that was found
                let aggregator_id = aggregator_ids[idx].aggregator_id;
                // Recompute the loading of this aggregator
                let new_load = AggregatorLoad::new(aggregator_id, &*self.sub_aggregators[&aggregator_id]);
                // Find where the aggregator should now be placed in the vector
                let new_index = aggregator_ids.binary_search(&new_load).unwrap_or_else(|x| x);
                // Replace the old invalid aggregator loading
                aggregator_ids[idx] = new_load;
                // Finally, shift the aggregator loading to the correct position
                if new_index > idx {
                    aggregator_ids[idx..new_index].rotate_left(1);
                }
            } else {
                // If an aggregator has not been found, then stop the distribution for now
                break;
            }
        }
        println!("Prove ------------");
        // Advance all the sub-aggregators and recombine proofs
        for (aggregator_id, aggregator) in self.sub_aggregators.iter_mut() {
            // Advance sub-aggregator
            aggregator.step();
            // Grab all the recursive proofs from this aggregator
            while let Some((batch_id, proof)) = aggregator.pop_recursive_proof() {
                let mut qualified_id = (*aggregator_id, batch_id);
                self.sub_recursive_proofs.insert(qualified_id, proof);
                // Finally, recombine all of the proofs from the sub-aggregators
                // A proof is a descendant of itself
                self.proof_descendants.insert(qualified_id, vec![qualified_id]);
                // Combine complete binary subtrees while it's possible
                while let Some(parent) = self.proof_parents.get(&qualified_id).copied() {
                    let children = self.proof_children[&parent];
                    match (self.proof_descendants.get(&children.0), self.proof_descendants.get(&children.1)) {
                        // Only combine complete subtrees
                        (Some(descendants0), Some(descendants1)) if descendants0.len() == descendants1.len() => {
                            // Remove the subtrees to ensure that recursive proving is not duplicated
                            let mut descendants0 = self.proof_descendants.remove(&children.0).unwrap();
                            let mut descendants1 = self.proof_descendants.remove(&children.1).unwrap();
                            self.proof_children.remove(&parent);
                            self.proof_parents.remove(&children.0);
                            self.proof_parents.remove(&children.1);
                            // Merge the descendants and store in preparation for a batch proof
                            descendants0.append(&mut descendants1);
                            self.proof_descendants.insert(parent, descendants0);
                            // Move to the parent
                            qualified_id = parent;
                        },
                        _ => break,
                    }
                }
            }
        }
        println!("Consolidate ------------");
        // Finally, create new batches to be recursively proved in future calls
        self.proof_descendants.retain(|qualified_id, descendants| {
            // Recombination is only required if there are multiple descendants
            if descendants.len() > 1 {
                // Grab the identified subproofs
                let proofs: Vec<_> = descendants
                    .into_iter()
                    .map(|x| self.sub_recursive_proofs.remove(&x).unwrap())
                    .collect();
                // And push them back into the queue
                assert_eq!(qualified_id.0, self.aggregator_id);
                println!("Planning aggregation of {} proofs", proofs.len());
                self.internal_proofs.push_back((qualified_id.1, proofs));
                // Do not retain these descendants otherwise combination work will be duplicated.
                // Do not even keep a singleton entry because that suggests that the merged proof
                // is ready.
                false
            } else if let Some(alias) = self.proof_aliases.remove(&qualified_id) {
                // Move root proofs to the output queue
                let root_proof = self.sub_recursive_proofs.remove(&descendants[0]).unwrap();
                self.recursive_proofs.push_back((alias, root_proof));
                // Processing of this proof is complete. Hence delete entry
                false
            } else {
                // Here we have a singleton that is not a root. Keep it around for future merges
                true
            }
        });
    }
}

/// An aggregator that computes a Merkle root of a batch of digests.
/// This acts as a worker node and does not delegate to further sub-aggregators.
pub struct MerkleAggregator<BatchIds: Iterator, AggregatorIds: Iterator> {
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: PhantomData<AggregatorIds>,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// Queue for raw leaf proofs (though normally pushed directly to internal for testing)
    pub leaf_queue: Vec<[u8; 32]>,
    /// Queue of batches waiting to be merklized
    pub internal_queue: VecDeque<(BatchIds::Item, Vec<[u8; 32]>)>,
    /// Queue of finished Merkle roots ready to be collected
    pub completed_proofs: VecDeque<(BatchIds::Item, [u8; 32])>,
}

impl<AggregatorIds: Iterator, BatchIds: Iterator> MerkleAggregator<BatchIds, AggregatorIds> {
    pub fn new(free_batch_ids: BatchIds) -> Self {
        Self {
            free_aggregator_ids: PhantomData,
            free_batch_ids,
            leaf_queue: Vec::new(),
            internal_queue: VecDeque::new(),
            completed_proofs: VecDeque::new(),
        }
    }

    /// A simple deterministic hash for testing purposes.
    /// In a real scenario, this would be replaced by a cryptographic hash like SHA-256 or Poseidon.
    fn combine_digests(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

impl<AggregatorIds: Iterator, BatchIds: Iterator> Aggregator for MerkleAggregator<BatchIds, AggregatorIds> where BatchIds::Item: Copy {
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Proof = [u8; 32];

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>) -> Self::BatchId {
        assert!(proofs.len().is_power_of_two(), "Merkle tree requires power-of-two leaves");
        assert!(proofs.len() > 1, "Must have more than one proof to aggregate");
        
        let batch_id = gen_id(&mut self.free_batch_ids);
        self.internal_queue.push_back((batch_id, proofs));
        
        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Proof)> {
        self.completed_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        self.leaf_queue.len()
            + self.internal_queue.iter().map(|(_, batch)| batch.len()).sum::<usize>()
    }

    fn proof_throughput(&self) -> f64 {
        // Returns 1.0 since this aggregator processes synchronously without parallelism
        1.0
    }

    fn insert_sub_aggregator(&mut self, _sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn remove_sub_aggregator(&mut self, _id: &Self::AggregatorId) -> Option<AggregatorBox<Self>> {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn step(&mut self) {
        // Pop one batch from the internal queue to process in this step
        while let Some((batch_id, mut current_layer)) = self.internal_queue.pop_front() {
            println!("Aggregating {} proofs", current_layer.len());
            // Iteratively compute the Merkle root
            while current_layer.len() > 1 {
                let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
                
                for chunk in current_layer.chunks_exact(2) {
                    let left = &chunk[0];
                    let right = &chunk[1];
                    next_layer.push(Self::combine_digests(left, right));
                }
                
                current_layer = next_layer;
            }
            
            // The single remaining element is the root
            let root = current_layer.pop().expect("Layer should contain exactly one root digest");
            self.completed_proofs.push_back((batch_id, root));
        }
    }
}

fn main() {
    let program_artifact_path = PathBuf::from("../circuits/target/recursive_no_zk_aggregation.json");
    let prover_file = PathBuf::from("../circuits/crates/recursive_no_zk_aggregation/Prover.toml");
    let overwrite_return = false;
    let target_directory_path = PathBuf::from("../circuits/target/");
    let witness_name = "recursive_no_zk_aggregation".to_string();
    //let contract_fn = None;
    //let oracle_file = None;
    //let oracle_resolver = None;
    let oracle_root_dir = PathBuf::from("../circuits/");
    let oracle_package_name = "recursive_no_zk_aggregation".to_string();

    let artifact = Artifact::read_from_file(&program_artifact_path).unwrap();
    let artifact_name = program_artifact_path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let Artifact::Program(program) = artifact else { panic!("incorrect artifact type") };
    let circuit = CompiledProgram::from(program);
    let circuit_name = artifact_name.to_string();
    // Construct foreign call executor for circuit execution
    let transcript_executor: layers::Either<ReplayForeignCallExecutor<_>, _> = layers::Either::Right(layers::Unhandled);

    let mut foreign_call_executor = DefaultForeignCallBuilder {
        output: std::io::stdout(),
        enable_mocks: false,
        resolver_url: None,
        root_path: None,
        package_name: None,
    }
    .build_with_base(transcript_executor);
    // Execute the circuit on the given inputs
    let blackbox_solver = Bn254BlackBoxSolver;
    let results = execution::execute(&circuit, &blackbox_solver, &mut foreign_call_executor, &prover_file);
    let results = results.expect("circuit execution error");
    // Extract the execution witness
    let compressed_witness_bytes = results.witness_stack.serialize().expect("output witness creation failed");
    // Grab the compressed program bytecode from the circuit
    let compressed_program_bytecode = Program::serialize_program_with_format(&circuit.program, SerializationFormat::default());

    // Decompress program bytecode
    let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_program_bytecode);
    let mut program_bytecode = Vec::new();
    gz_decoder.read_to_end(&mut program_bytecode).unwrap();
    // Use the FFI backend which links directly to static libraries
    let backend = FfiBackend::new().unwrap();
    // Initialize the Barretenberg API
    let mut api = BarretenbergApi::new(backend);
    const NUM_POINTS: u32 = 1 << 24;
    // CRS parameters are stored relative to home directory
    let home_dir = std::env::home_dir().expect("unable to get home directory");
    // Sub-directory of the home directory containing the CRS parameters
    let crs_path = home_dir.join(CRS_DIR);
    // Read G1 point data
    let g1_data = std::fs::read(crs_path.join(G1_UNCOMPRESSED_DATA_PATH)).expect("unable to read G1 data");
    // Read G2 point data
    let g2_data = std::fs::read(crs_path.join(G2_UNCOMPRESSED_DATA_PATH)).expect("unable to read G2 data");
    // Initialize the global CRS
    let init_srs_response = api.srs_init_srs(&g1_data, NUM_POINTS, &g2_data).expect("unable to initialize the global CRS");
    // Proof system settings to use for generating the verification key
    let proof_system_settings = ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "keccak".to_string(),
        disable_zk: true,
        optimized_solidity_verifier: false,
    };
    // The circuit to generate a verification key for
    let circuit_input = CircuitInputNoVK { name: circuit_name.clone(), bytecode: program_bytecode.clone() };
    // Compute the verification key
    let response = api.circuit_compute_vk(circuit_input, proof_system_settings.clone()).unwrap();
    println!("Hash: {:?}", response.hash);

    // Decompress witness bytes
    let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_witness_bytes);
    let mut witness_bytes = Vec::new();
    gz_decoder.read_to_end(&mut witness_bytes).unwrap();
    // The circuit to generate a proof from
    let circuit_input = CircuitInput { name: circuit_name, bytecode: program_bytecode, verification_key: response.bytes };
    // Compute the proof from the witness bytes
    let response = api.circuit_prove(circuit_input, &witness_bytes, proof_system_settings).unwrap();
    println!("Proof: {:?}", response.proof);
    // Finally destroy the backend
    api.destroy().unwrap();
}

proptest! {
    #[test]
    fn test_balanced_aggregator(batch: [[u8; 32]; 256]) {
        type MerkleAggregatorT = MerkleAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT = RecursiveAggregator<[u8; 32], RangeFrom<usize>, RangeFrom<usize>>;
        // Make a simple aggregator that directly computes the root
        let mut merkle_aggregator = MerkleAggregatorT::new(0usize..);
        // Push the random batch onto the aggregator
        merkle_aggregator.push_internal_proofs(batch.to_vec());
        // Make the aggregator process the proofs in the queue
        merkle_aggregator.step();
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push 4 sub-aggregators to actually handle the computations
        recursive_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        // Push some work onto the recursive aggregator
        recursive_aggregator.push_internal_proofs(batch.to_vec());
        // Repeatedly step through distribution and consolidation
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        // Finally, ensure that the Merkle roots agree
        assert_eq!(merkle_aggregator.pop_recursive_proof(), recursive_aggregator.pop_recursive_proof());
        assert_eq!(merkle_aggregator.pop_recursive_proof(), None);
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }

    #[test]
    fn test_imbalanced_aggregator(batch: [[u8; 32]; 256]) {
        type MerkleAggregatorT = MerkleAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT = RecursiveAggregator<[u8; 32], RangeFrom<usize>, RangeFrom<usize>>;
        // Make a simple aggregator that directly computes the root
        let mut merkle_aggregator = MerkleAggregatorT::new(0usize..);
        // Push the random batch onto the aggregator
        merkle_aggregator.push_internal_proofs(batch.to_vec());
        // Make the aggregator process the proofs in the queue
        merkle_aggregator.step();
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push 2 sub-aggregators to handle the computations
        recursive_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        // Let one of the sub-aggregators itself be a recursive aggregator
        let mut recursive_sub_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        recursive_sub_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_sub_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_sub_aggregator.insert_sub_aggregator(Box::new(MerkleAggregatorT::new(0usize..)));
        recursive_aggregator.insert_sub_aggregator(Box::new(recursive_sub_aggregator));
        // Push some work onto the recursive aggregator
        recursive_aggregator.push_internal_proofs(batch.to_vec());
        // Repeatedly step through distribution and consolidation
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        recursive_aggregator.step();
        // Finally, ensure that the Merkle roots agree
        assert_eq!(merkle_aggregator.pop_recursive_proof(), recursive_aggregator.pop_recursive_proof());
        assert_eq!(merkle_aggregator.pop_recursive_proof(), None);
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }
}
