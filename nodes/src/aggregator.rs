use acir::AcirField;
use acir::FieldElement;
use acir::SerializationFormat;
use acir::circuit::Program;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::CircuitComputeVkResponse;
use barretenberg_rs::generated_types::ProofSystemSettings;
use barretenberg_rs::generated_types::{CircuitInput, CircuitInputNoVK};
use barretenberg_rs::generated_types::CircuitProveResponse;
use barretenberg_rs::generated_types::CircuitVerifyResponse;
use barretenberg_rs::BarretenbergError;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use borsh::{BorshDeserialize, BorshSerialize};
use nargo::foreign_calls::transcript::ReplayForeignCallExecutor;
use nargo::foreign_calls::{DefaultForeignCallBuilder, layers};
use noir_artifact_cli::Artifact;
use noir_artifact_cli::execution::ExecutionResults;
use noir_artifact_cli::execution::ReturnValues;
use noirc_abi::InputMap;
use noirc_abi::input_parser::InputValue;
use noirc_artifacts::program::CompiledProgram;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

/// Path to file containing the aggregation circuit
const AGGREGATION_CIRCUIT_PATH: &str = "../circuits/target/recursive_no_zk_aggregation.json";
/// Wait time beyond which a sub-aggregator should not be loaded
const MAX_WAIT_TIME: f64 = 2.0;

/// Type alias to ease generic usage of aggregators
type AggregatorBox<A> = Box<
    dyn Aggregator<
            AggregatorId = <A as Aggregator>::AggregatorId,
            Node = <A as Aggregator>::Node,
            BatchId = <A as Aggregator>::BatchId,
        >,
>;

/// The interface shared by all proof aggregators
pub trait Aggregator {
    /// The type that holds aggregator IDs
    type AggregatorId;
    /// The type that holds batch IDs
    type BatchId;
    /// The type that holds proofs
    type Node;
    /// Push a batch of proofs to aggregate onto a queue
    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId;
    /// Pop a recursive proof from the queue of aggregations
    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)>;
    /// Get the number of remaining aggregations to do
    fn pending_queue_size(&self) -> usize;
    /// Get the rate at which proofs are aggregated in a unit of time. Return value must be >= 1.
    fn proof_throughput(&self) -> f64;
    /// Add a sub-aggregator that will help in aggregating proofs
    fn insert_sub_aggregator(&mut self, sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId;
    /// Remove the given sub-aggregator from the set of helpers
    fn remove_sub_aggregator(&mut self, id: &Self::AggregatorId);
    /// Consume leaf and internal proofs and produce aggregate proofs
    fn step(&mut self);
    /// Ensure that subsequent queries return correct results
    fn sync(&mut self);
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
            aggregator.pending_queue_size() as f64 / (2.0 * proof_throughput)
        };
        Self {
            expected_wait_time,
            negative_throughput: -proof_throughput,
            aggregator_id,
        }
    }
}

impl<AggregatorId: PartialEq> Eq for AggregatorLoad<AggregatorId> {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl<AggregatorId: PartialOrd> Ord for AggregatorLoad<AggregatorId> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other)
            .expect("malformed AggregatorLoad object")
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
    pub sub_aggregators: HashMap<
        AggregatorIds::Item,
        Box<
            dyn Aggregator<
                    AggregatorId = AggregatorIds::Item,
                    BatchId = BatchIds::Item,
                    Node = Proof,
                >,
        >,
    >,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: AggregatorIds,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// Map proofs to their parents
    pub proof_parents:
        HashMap<(AggregatorIds::Item, BatchIds::Item), (AggregatorIds::Item, BatchIds::Item)>,
    /// Map proofs to their children
    pub proof_children: HashMap<
        (AggregatorIds::Item, BatchIds::Item),
        (
            (AggregatorIds::Item, BatchIds::Item),
            (AggregatorIds::Item, BatchIds::Item),
        ),
    >,
    /// Map qualified batch IDs to their original batch IDs
    pub proof_aliases: HashMap<(AggregatorIds::Item, BatchIds::Item), BatchIds::Item>,
    /// Map qualified batch ID to vector of its leaf descendants
    pub proof_descendants:
        BTreeMap<(AggregatorIds::Item, BatchIds::Item), Vec<(AggregatorIds::Item, BatchIds::Item)>>,
}

impl<Proof, BatchIds: Iterator, AggregatorIds: Iterator>
    RecursiveAggregator<Proof, BatchIds, AggregatorIds>
{
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

impl<AggregatorIds: Iterator, BatchIds: Iterator, Proof> Aggregator
    for RecursiveAggregator<Proof, BatchIds, AggregatorIds>
where
    AggregatorIds::Item: Hash + Eq + Copy + Debug + PartialOrd + Ord + Display,
    BatchIds::Item: Hash + Eq + Copy + Ord + Debug,
{
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Node = Proof;

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId {
        // Batch sizes must be powers of two
        assert!(proofs.len().is_power_of_two());
        // More than one proof must be supplied for there to be work to do
        assert!(proofs.len() > 1);
        let batch_id = gen_id(&mut self.free_batch_ids);
        self.internal_proofs.push_back((batch_id, proofs));
        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        // Get the proofs queued in this aggregator
        let local = self
            .internal_proofs
            .iter()
            .map(|s| s.1.len())
            .sum::<usize>();
        // Get the proofs queued in the sub-aggregators
        let delegated: usize = self
            .sub_aggregators
            .values()
            .map(|agg| agg.pending_queue_size())
            .sum();
        // Return the total proofs queued
        local + delegated
    }

    fn proof_throughput(&self) -> f64 {
        // The throughput of a recursive aggregator is the sum of those of its sub-aggregators
        self.sub_aggregators
            .values()
            .map(|x| x.proof_throughput())
            .sum()
    }

    fn insert_sub_aggregator(&mut self, sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId {
        // Save the sub-aggregator with the given free ID
        let aggregator_id = gen_id(&mut self.free_aggregator_ids);
        self.sub_aggregators.insert(aggregator_id, sub_aggregator);
        aggregator_id
    }

    fn remove_sub_aggregator(&mut self, id: &Self::AggregatorId) {
        self.sub_aggregators.remove(id);
    }

    fn sync(&mut self) {
        // Synchronize all the sub-aggregators
        for aggregator in self.sub_aggregators.values_mut() {
            aggregator.sync();
        }
    }

    fn step(&mut self) {
        println!("Distribute ------------");
        // Compute the current aggregator loads
        let mut aggregator_ids: Vec<_> = self
            .sub_aggregators
            .iter_mut()
            .map(|(id, agg)| {
                agg.sync();
                AggregatorLoad::new(*id, &**agg)
            })
            .collect();
        // Sort the aggregator IDs starting with the least loaded one first
        aggregator_ids.sort();
        // Get the total number of proofs that need to be distributed amongst aggregators
        let mut pending_queue_size = self
            .internal_proofs
            .iter()
            .map(|s| s.1.len())
            .sum::<usize>();
        // While there are still pending proofs, distribute them amongst aggregators
        while pending_queue_size > 0 {
            // Indicates whether an appropriate aggregator to do the work has been found
            let mut aggregator_idx = None;
            // Now try to place some pending proofs at the least loaded aggregator that can be saturated
            for (idx, id) in aggregator_ids.iter().enumerate() {
                // Number of proofs required to saturate the aggregator
                let proof_throughput = -id.negative_throughput as usize * 2;
                // Only send the prefix of the queue if it can saturate this aggregator
                if pending_queue_size < proof_throughput || id.expected_wait_time >= MAX_WAIT_TIME {
                    continue;
                }
                // Indicate that an aggregator has been found
                aggregator_idx = Some(idx);
                let mut total_chunk_size = 0;
                // Take as many chunks as required to saturate the aggregator
                while total_chunk_size < proof_throughput {
                    // Compute the amount that needs to be drained to saturate the current aggregator
                    let (mut batch_id, mut batch) = self.internal_proofs.pop_front().unwrap();
                    let mut qualified_batch_id = (self.aggregator_id, batch_id);
                    let target_size =
                        std::cmp::min(proof_throughput.next_power_of_two(), batch.len());
                    // Keep splitting off batches (that are powers of two) until we get to the correct size
                    while batch.len() > target_size {
                        // These remainder batches will be processed in future loops
                        let batch1_id = gen_id(&mut self.free_batch_ids);
                        let batch1 = batch.split_off(batch.len() / 2);
                        self.internal_proofs.push_front((batch1_id, batch1));
                        // Maintain a tree of proof dependencies
                        batch_id = gen_id(&mut self.free_batch_ids);
                        self.proof_parents
                            .insert((self.aggregator_id, batch_id), qualified_batch_id);
                        self.proof_parents
                            .insert((self.aggregator_id, batch1_id), qualified_batch_id);
                        self.proof_children.insert(
                            qualified_batch_id,
                            (
                                (self.aggregator_id, batch_id),
                                (self.aggregator_id, batch1_id),
                            ),
                        );
                        qualified_batch_id = (self.aggregator_id, batch_id);
                    }
                    // Add the drainage to the sub aggregator
                    total_chunk_size += batch.len();
                    println!(
                        "Sending {} proofs to aggregator {}",
                        batch.len(),
                        id.aggregator_id
                    );
                    let new_batch_id = self
                        .sub_aggregators
                        .get_mut(&id.aggregator_id)
                        .unwrap()
                        .push_internal_proofs(batch);
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
                if let Some(x) = self.sub_aggregators.get_mut(&aggregator_id) {
                    x.sync()
                }
                let new_load =
                    AggregatorLoad::new(aggregator_id, &*self.sub_aggregators[&aggregator_id]);
                // Find where the aggregator should now be placed in the vector
                let new_index = aggregator_ids
                    .binary_search(&new_load)
                    .unwrap_or_else(|x| x);
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
            aggregator.sync();
            // Grab all the recursive proofs from this aggregator
            while let Some((batch_id, proof)) = aggregator.pop_recursive_proof() {
                let mut qualified_id = (*aggregator_id, batch_id);
                self.sub_recursive_proofs.insert(qualified_id, proof);
                // Finally, recombine all of the proofs from the sub-aggregators
                // A proof is a descendant of itself
                self.proof_descendants
                    .insert(qualified_id, vec![qualified_id]);
                // Combine complete binary subtrees while it's possible
                while let Some(parent) = self.proof_parents.get(&qualified_id).copied() {
                    let children = self.proof_children[&parent];
                    match (
                        self.proof_descendants.get(&children.0),
                        self.proof_descendants.get(&children.1),
                    ) {
                        // Only combine complete subtrees
                        (Some(descendants0), Some(descendants1))
                            if descendants0.len() == descendants1.len() =>
                        {
                            // Remove the subtrees to ensure that recursive proving is not duplicated
                            let mut descendants0 =
                                self.proof_descendants.remove(&children.0).unwrap();
                            let mut descendants1 =
                                self.proof_descendants.remove(&children.1).unwrap();
                            self.proof_children.remove(&parent);
                            self.proof_parents.remove(&children.0);
                            self.proof_parents.remove(&children.1);
                            // Merge the descendants and store in preparation for a batch proof
                            descendants0.append(&mut descendants1);
                            self.proof_descendants.insert(parent, descendants0);
                            // Move to the parent
                            qualified_id = parent;
                        }
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
                    .iter()
                    .map(|x| self.sub_recursive_proofs.remove(x).unwrap())
                    .collect();
                // And push them back into the queue
                assert_eq!(qualified_id.0, self.aggregator_id);
                println!("Planning aggregation of {} proofs", proofs.len());
                self.internal_proofs.push_front((qualified_id.1, proofs));
                // Do not retain these descendants otherwise combination work will be duplicated.
                // Do not even keep a singleton entry because that suggests that the merged proof
                // is ready.
                false
            } else if let Some(alias) = self.proof_aliases.remove(qualified_id) {
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

impl<AggregatorIds: Iterator, BatchIds: Iterator> Aggregator
    for MerkleAggregator<BatchIds, AggregatorIds>
where
    BatchIds::Item: Copy,
{
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Node = [u8; 32];

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId {
        assert!(
            proofs.len().is_power_of_two(),
            "Merkle tree requires power-of-two leaves"
        );
        assert!(
            proofs.len() > 1,
            "Must have more than one proof to aggregate"
        );

        let batch_id = gen_id(&mut self.free_batch_ids);
        self.internal_queue.push_back((batch_id, proofs));

        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)> {
        self.completed_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        self.leaf_queue.len()
            + self
                .internal_queue
                .iter()
                .map(|(_, batch)| batch.len())
                .sum::<usize>()
    }

    fn proof_throughput(&self) -> f64 {
        // Returns 1.0 since this aggregator processes synchronously without parallelism
        1.0
    }

    fn insert_sub_aggregator(
        &mut self,
        _sub_aggregator: AggregatorBox<Self>,
    ) -> Self::AggregatorId {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn remove_sub_aggregator(&mut self, _id: &Self::AggregatorId) {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn sync(&mut self) {}

    fn step(&mut self) {
        // Pop one batch from the internal queue to process in this step
        if let Some((batch_id, mut current_layer)) = self.internal_queue.pop_front() {
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
            let root = current_layer
                .pop()
                .expect("Layer should contain exactly one root digest");
            self.completed_proofs.push_back((batch_id, root));
        }
    }
}

/// Commands sent from the main thread to the worker thread.
pub enum ThreadRequest<BatchId, A: Aggregator> {
    /// Push new batch of internal proofs
    PushInternalProofs(BatchId, Vec<A::Node>),
    /// Synchronize the worker
    Sync,
    /// Move the worker forward a step
    Step,
    /// Shutdown the worker
    Shutdown,
}

/// Updates sent from the worker thread back to the main thread
pub enum ThreadResponse<BatchId, A: Aggregator> {
    /// Post new recursive proof
    RecursiveProof(BatchId, A::Node),
    /// Former number is the outer queue delta. Latter is new inner pending queue size.
    PendingQueueSize(usize, usize),
    /// Update the proof throughput value
    ProofThroughput(f64),
}

/// An aggregator that wraps a blocking aggregator and runs it in a separate background thread.
pub struct ThreadedAggregator<BatchIds: Iterator, AggregatorIds: Iterator, A: Aggregator> {
    /// Channel to send data to the aggregator
    pub sender: mpsc::Sender<ThreadRequest<BatchIds::Item, A>>,
    /// Channel to receive data from the aggregator
    pub receiver: mpsc::Receiver<ThreadResponse<BatchIds::Item, A>>,
    /// Handle to thee aggregator's thread
    pub handle: Option<thread::JoinHandle<()>>,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: AggregatorIds,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// The size of the inner queue of pending nodes
    pub inner_pending_queue_size: usize,
    /// The size of the outer queue of pending nodes
    pub outer_pending_queue_size: usize,
    /// The proofs processed per unit of time
    pub proof_throughput: f64,
    /// Queue of produced recursive proofs
    pub recursive_proofs: VecDeque<(BatchIds::Item, A::Node)>,
}

impl<A, BatchIds: Iterator, AggregatorIds: Iterator> ThreadedAggregator<BatchIds, AggregatorIds, A>
where
    A: Aggregator + 'static,
    A::Node: Send,
    A::BatchId: Send + Eq + Hash,
    A::AggregatorId: Send + Eq + Hash,
    AggregatorIds::Item: Send + Hash + Eq + 'static,
    BatchIds::Item: Send + Hash + Eq + 'static,
{
    /// Creates a new threaded aggregator, spawning a background thread to handle its workload.
    pub fn new<F: 'static + Send + Fn() -> A>(
        free_batch_ids: BatchIds,
        free_aggregator_ids: AggregatorIds,
        inner: F,
    ) -> Self {
        // Enable two-way communication between parent and child
        let (parent_tx, child_rx) = mpsc::channel();
        let (child_tx, parent_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let mut inner = inner();
            let mut batch_aliases = HashMap::new();
            // Process commands from parent in a loop
            while let Ok(cmd) = child_rx.recv() {
                // Number of internal proofs pushed during this iteration
                let mut internal_proofs_pushed = 0;
                // Forward the command to the inner aggregator
                match cmd {
                    ThreadRequest::PushInternalProofs(outer_id, proofs) => {
                        internal_proofs_pushed += proofs.len();
                        let inner_id = inner.push_internal_proofs(proofs);
                        batch_aliases.insert(inner_id, outer_id);
                    }
                    ThreadRequest::Step => inner.step(),
                    ThreadRequest::Sync => inner.sync(),
                    ThreadRequest::Shutdown => break,
                }
                // Send any new recursive proofs back to the parent
                while let Some((inner_id, node)) = inner.pop_recursive_proof() {
                    let outer_id = batch_aliases.remove(&inner_id).expect("unknown inner ID");
                    child_tx
                        .send(ThreadResponse::RecursiveProof(outer_id, node))
                        .unwrap();
                }
                // Also send the new throughput and pending queue size back to the parent
                child_tx
                    .send(ThreadResponse::ProofThroughput(inner.proof_throughput()))
                    .unwrap();
                child_tx
                    .send(ThreadResponse::PendingQueueSize(
                        internal_proofs_pushed,
                        inner.pending_queue_size(),
                    ))
                    .unwrap();
            }
        });

        Self {
            sender: parent_tx,
            receiver: parent_rx,
            handle: Some(handle),
            free_batch_ids,
            free_aggregator_ids,
            inner_pending_queue_size: 0,
            outer_pending_queue_size: 0,
            proof_throughput: 1.0,
            recursive_proofs: VecDeque::new(),
        }
    }
}

impl<A, BatchIds: Iterator, AggregatorIds: Iterator> Drop
    for ThreadedAggregator<BatchIds, AggregatorIds, A>
where
    A: Aggregator,
{
    fn drop(&mut self) {
        // Signal the worker thread to exit, ignoring any sending errors if it already panicked/died.
        self.sender.send(ThreadRequest::Shutdown).unwrap();
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

impl<A, BatchIds: Iterator, AggregatorIds: Iterator> Aggregator
    for ThreadedAggregator<BatchIds, AggregatorIds, A>
where
    A: Aggregator<BatchId = BatchIds::Item, AggregatorId = AggregatorIds::Item> + 'static,
    A::Node: Send,
    A::BatchId: Send + Eq + Hash,
    A::AggregatorId: Send + Copy + Eq + Hash,
    BatchIds::Item: Copy,
{
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Node = A::Node;

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId {
        // Speculatively update the queue size. This will eventually be overwritten.
        self.outer_pending_queue_size += proofs.len();
        // Create a batch ID to immediately return to caller.
        let batch_id = gen_id(&mut self.free_batch_ids);
        // Let the child thread manage the mappings between outer and inner batch IDs.
        self.sender
            .send(ThreadRequest::PushInternalProofs(batch_id, proofs))
            .unwrap();
        batch_id
    }

    fn insert_sub_aggregator(
        &mut self,
        _sub_aggregator: AggregatorBox<Self>,
    ) -> Self::AggregatorId {
        unimplemented!("ThreadedAggregator does not support sub-aggregators.");
    }

    fn remove_sub_aggregator(&mut self, _id: &Self::AggregatorId) {
        unimplemented!("ThreadedAggregator does not support sub-aggregators.");
    }

    fn step(&mut self) {
        self.sender.send(ThreadRequest::Step).unwrap();
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        self.inner_pending_queue_size + self.outer_pending_queue_size
    }

    fn proof_throughput(&self) -> f64 {
        self.proof_throughput
    }

    fn sync(&mut self) {
        // Update the object state with data from the inner thread
        while let Ok(resp) = self.receiver.try_recv() {
            match resp {
                ThreadResponse::PendingQueueSize(delta, new_size) => {
                    self.outer_pending_queue_size -= delta;
                    self.inner_pending_queue_size = new_size;
                }
                ThreadResponse::ProofThroughput(throughput) => {
                    self.proof_throughput = throughput;
                }
                ThreadResponse::RecursiveProof(batch_id, node) => {
                    self.recursive_proofs.push_back((batch_id, node));
                }
            }
        }
        // Command the inner aggregator to synchronize
        self.sender.send(ThreadRequest::Sync).unwrap();
    }
}

/// Holds all data necessary to verify a proof within the aggregation circuit
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerifierInputs {
    /// The hash of the verification key
    pub key_hash: Vec<u8>,
    /// The actual proof to be verified
    pub proof: Vec<Vec<u8>>,
    /// The public inputs used to generate the proof
    pub public_inputs: Vec<u8>,
    /// The verification key that's used to verify the proof
    pub verification_key: Vec<Vec<u8>>,
}

impl From<VerifierInputs> for InputMap {
    /// Convert the serializable proof struct into an InputMap for the ABI.
    fn from(proof: VerifierInputs) -> Self {
        let mut map = InputMap::new();
        map.insert(
            "key_hash".to_string(),
            InputValue::Field(FieldElement::from_be_bytes_reduce(&proof.key_hash)),
        );
        map.insert(
            "proof".to_string(),
            InputValue::Vec(
                proof
                    .proof
                    .into_iter()
                    .map(|x| InputValue::Field(FieldElement::from_be_bytes_reduce(&x)))
                    .collect(),
            ),
        );
        map.insert(
            "public_inputs".to_string(),
            InputValue::Field(FieldElement::from_be_bytes_reduce(&proof.public_inputs)),
        );
        map.insert(
            "verification_key".to_string(),
            InputValue::Vec(
                proof
                    .verification_key
                    .into_iter()
                    .map(|x| InputValue::Field(FieldElement::from_be_bytes_reduce(&x)))
                    .collect(),
            ),
        );
        map
    }
}

pub struct BarretenbergCircuit {
    /// The aggregation circuit
    pub circuit: CompiledProgram,
    /// The response from computing the verification key
    pub compute_vk_response: CircuitComputeVkResponse,
    /// Settings to use for proving
    pub proof_system_settings: ProofSystemSettings,
    /// Name of the aggregation circuit
    pub circuit_name: String,
    /// Bytecode of the aggregation circuit
    pub program_bytecode: Vec<u8>,
}

impl BarretenbergCircuit {
    /// Load up the aggregation circuit from disk
    pub fn new(api: &mut BarretenbergApi<FfiBackend>, program_artifact_path: PathBuf) -> Self {
        let artifact_name = program_artifact_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let circuit_name = artifact_name.to_string();
        // Load up the aggregation circuit from disk
        let artifact = Artifact::read_from_file(&program_artifact_path).unwrap();
        let Artifact::Program(program) = artifact else {
            panic!("incorrect artifact type")
        };
        let circuit = CompiledProgram::from(program);
        // Grab the compressed program bytecode from the circuit
        let compressed_program_bytecode = Program::serialize_program_with_format(
            &circuit.program,
            SerializationFormat::default(),
        );

        // Decompress program bytecode
        let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_program_bytecode);
        let mut program_bytecode = Vec::new();
        gz_decoder.read_to_end(&mut program_bytecode).unwrap();

        // Proof system settings to use for generating the verification key
        let proof_system_settings = ProofSystemSettings {
            ipa_accumulation: false,
            oracle_hash_type: "poseidon2".to_string(),
            disable_zk: true,
            optimized_solidity_verifier: false,
        };
        // The circuit to generate a verification key for
        let circuit_input = CircuitInputNoVK {
            name: circuit_name.clone(),
            bytecode: program_bytecode.clone(),
        };
        // Compute the verification key
        let compute_vk_response = api
            .circuit_compute_vk(circuit_input, proof_system_settings.clone())
            .unwrap();
        Self {
            circuit,
            compute_vk_response,
            proof_system_settings,
            circuit_name,
            program_bytecode,
        }
    }

    pub fn circuit_prove(
        &mut self,
        api: &mut BarretenbergApi<FfiBackend>,
        input_map: InputMap,
    ) -> Result<CircuitProveResponse, BarretenbergError> {
        let expected_return = None;
        let initial_witness = self
            .circuit
            .abi
            .encode(&input_map, None)
            .expect("unable to encode initial witness");

        // Construct foreign call executor for circuit execution
        let transcript_executor: layers::Either<ReplayForeignCallExecutor<_>, _> =
            layers::Either::Right(layers::Unhandled);

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
        let witness_stack = nargo::ops::execute_program(
            &self.circuit.program,
            initial_witness,
            &blackbox_solver,
            &mut foreign_call_executor,
        )
        .expect("circuit execution error");
        // Extract certain witnesses from the stack
        let main_witness = &witness_stack
            .peek()
            .expect("Should have at least one witness on the stack")
            .witness;

        let (_, actual_return) = self
            .circuit
            .abi
            .decode(main_witness)
            .expect("unable to decode main witness");
        let results = ExecutionResults {
            witness_stack,
            return_values: ReturnValues {
                actual_return,
                expected_return,
            },
        };
        // Extract the execution witness
        let compressed_witness_bytes = results
            .witness_stack
            .serialize()
            .expect("output witness creation failed");

        // Decompress witness bytes
        let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_witness_bytes);
        let mut witness_bytes = Vec::new();
        gz_decoder.read_to_end(&mut witness_bytes).unwrap();
        // The circuit to generate a proof from
        let circuit_input = CircuitInput {
            name: self.circuit_name.clone(),
            bytecode: self.program_bytecode.clone(),
            verification_key: self.compute_vk_response.bytes.clone(),
        };
        // Compute the proof from the witness bytes
        api.circuit_prove(
            circuit_input,
            &witness_bytes,
            self.proof_system_settings.clone(),
        )
    }

    fn circuit_verify(
        &mut self,
        api: &mut BarretenbergApi<FfiBackend>,
        prove_response: CircuitProveResponse,
    ) -> Result<CircuitVerifyResponse, BarretenbergError> {
        api.circuit_verify(
            &self.compute_vk_response.bytes,
            prove_response.public_inputs,
            prove_response.proof,
            self.proof_system_settings.clone(),
        )
    }
}

/// An aggregator that computes a Merkle root of a batch of digests.
/// This acts as a worker node and does not delegate to further sub-aggregators.
pub struct BarretenbergAggregator<BatchIds: Iterator, AggregatorIds: Iterator> {
    /// The Barretenberg API used to generate and verify proofs
    pub api: BarretenbergApi<FfiBackend>,
    /// The aggregation circuit
    pub circuit: BarretenbergCircuit,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: PhantomData<AggregatorIds>,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// Queue for raw leaf proofs (though normally pushed directly to internal for testing)
    pub leaf_queue: Vec<[u8; 32]>,
    /// Queue of batches waiting to be merklized
    pub internal_queue: VecDeque<(BatchIds::Item, Vec<VerifierInputs>)>,
    /// Queue of finished Merkle roots ready to be collected
    pub completed_proofs: VecDeque<(BatchIds::Item, VerifierInputs)>,
}

impl<AggregatorIds: Iterator, BatchIds: Iterator> BarretenbergAggregator<BatchIds, AggregatorIds> {
    pub fn new(free_batch_ids: BatchIds) -> Self {
        // Load up the aggregation circuit from disk
        let program_artifact_path = PathBuf::from(AGGREGATION_CIRCUIT_PATH);
        // Use the FFI backend which links directly to static libraries
        let backend = FfiBackend::new().unwrap();
        // Initialize the Barretenberg API
        let mut api = BarretenbergApi::new(backend);
        // Load up the aggregation circuit from disk
        let circuit = BarretenbergCircuit::new(&mut api, program_artifact_path);
        Self {
            api,
            free_aggregator_ids: PhantomData,
            free_batch_ids,
            leaf_queue: Vec::new(),
            internal_queue: VecDeque::new(),
            completed_proofs: VecDeque::new(),
            circuit,
        }
    }

    /// Combine the given two recursive proofs into a single one
    fn combine_proofs(&mut self, left: VerifierInputs, right: VerifierInputs) -> VerifierInputs {
        // Combine the left and right input maps into one map to produce an aggregate proof
        let left = InputMap::from(left);
        let mut right = InputMap::from(right);
        let input_map: InputMap = left
            .into_iter()
            .map(|(k, left_value)| {
                let right_value = right
                    .remove(&k)
                    .expect("left map has keys not in the right map");
                (k, InputValue::Vec(vec![left_value, right_value]))
            })
            .collect();
        assert!(right.is_empty(), "right map has keys not in the left map");
        // Compute the proof from the witness bytes
        let prove_response = self.circuit.circuit_prove(&mut self.api, input_map).unwrap();
        let verify_response = self.circuit.circuit_verify(&mut self.api, prove_response.clone()).unwrap();
        println!("Verification response: {:?}", verify_response);
        // Finally, make an output map representing the combined proofs
        VerifierInputs {
            key_hash: self.circuit.compute_vk_response.hash.clone(),
            proof: prove_response.proof,
            public_inputs: prove_response.public_inputs[0].clone(),
            verification_key: self.circuit.compute_vk_response.fields.clone(),
        }
    }
}

impl<AggregatorIds: Iterator, BatchIds: Iterator> Drop
    for BarretenbergAggregator<BatchIds, AggregatorIds>
{
    fn drop(&mut self) {
        self.api.shutdown().unwrap();
    }
}

impl<AggregatorIds: Iterator, BatchIds: Iterator> Aggregator
    for BarretenbergAggregator<BatchIds, AggregatorIds>
where
    BatchIds::Item: Copy,
{
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Node = VerifierInputs;

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId {
        assert!(
            proofs.len().is_power_of_two(),
            "Merkle tree requires power-of-two leaves"
        );
        assert!(
            proofs.len() > 1,
            "Must have more than one proof to aggregate"
        );

        let batch_id = gen_id(&mut self.free_batch_ids);
        self.internal_queue.push_back((batch_id, proofs));

        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)> {
        self.completed_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        self.leaf_queue.len()
            + self
                .internal_queue
                .iter()
                .map(|(_, batch)| batch.len())
                .sum::<usize>()
    }

    fn proof_throughput(&self) -> f64 {
        // Returns 1.0 since this aggregator processes synchronously without parallelism
        1.0
    }

    fn insert_sub_aggregator(
        &mut self,
        _sub_aggregator: AggregatorBox<Self>,
    ) -> Self::AggregatorId {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn remove_sub_aggregator(&mut self, _id: &Self::AggregatorId) {
        unimplemented!("MerkleAggregator is a leaf worker and does not support sub-aggregators.");
    }

    fn sync(&mut self) {}

    fn step(&mut self) {
        // Pop one batch from the internal queue to process in this step
        if let Some((batch_id, mut current_layer)) = self.internal_queue.pop_front() {
            println!("Aggregating {} proofs", current_layer.len());
            // Iteratively compute the Merkle root
            while current_layer.len() > 1 {
                let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
                let mut iter = current_layer.into_iter();
                while let (Some(left), Some(right)) = (iter.next(), iter.next()) {
                    next_layer.push(self.combine_proofs(left, right));
                }

                current_layer = next_layer;
            }

            // The single remaining element is the root
            let root = current_layer
                .pop()
                .expect("Layer should contain exactly one root digest");
            self.completed_proofs.push_back((batch_id, root));
        }
    }
}

/// Represents a non-blocking buffered stream
pub struct BufferedStream {
    /// The stream being wrapped
    pub stream: TcpStream,
    /// Buffer containing some bytes read
    pub read_buf: Vec<u8>,
    /// Buffer containing bytes to be written
    pub write_buf: Vec<u8>,
}

impl BufferedStream {
    /// Wrap the given stream and make it non-blocking
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    /// Reads bytes from the stream into a buffer
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let output_buf_len = buf.len();
        let read_buf_len = self.read_buf.len();
        if output_buf_len <= read_buf_len {
            // If read buffer contains enough bytes to saturate parameter
            // Then move the read buffer's prefix into the parameter
            buf.copy_from_slice(&self.read_buf[..buf.len()]);
            self.read_buf.drain(..buf.len());
            Ok(output_buf_len)
        } else {
            // Otherwise, read as many bytes as possible from the steam
            let bytes_read = self.stream.read(&mut buf[read_buf_len..])?;
            // Move bytes from the read buffer into the output buffer
            buf[..read_buf_len].copy_from_slice(&self.read_buf[..]);
            self.read_buf.clear();
            Ok(read_buf_len + bytes_read)
        }
    }

    /// Either fill the given buffer, or buffer what's read
    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let output_buf_len = buf.len();
        let read_buf_len = self.read_buf.len();
        if output_buf_len <= read_buf_len {
            // If read buffer contains enough bytes to saturate parameter
            // Then move the read buffer's prefix into the parameter
            buf.copy_from_slice(&self.read_buf[..output_buf_len]);
            self.read_buf.drain(..output_buf_len);
            Ok(())
        } else {
            // If read buffer contains insufficient bytes to saturate parameter
            // Then just read the remaining bytes from the stream into the suffix
            let mut bytes_read = self.stream.read(&mut buf[read_buf_len..])?;
            // New total number of bytes buffered
            bytes_read += read_buf_len;
            if bytes_read == read_buf_len {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else if bytes_read < output_buf_len {
                // Copy bytes from the output buffer into the read buffer
                self.read_buf
                    .extend_from_slice(&buf[read_buf_len..bytes_read]);
                // Try to read more bytes
                self.read_exact(buf)
            } else {
                assert_eq!(bytes_read, output_buf_len);
                // Move bytes from the read buffer into the output buffer
                buf[..read_buf_len].copy_from_slice(&self.read_buf[..]);
                self.read_buf.clear();
                Ok(())
            }
        }
    }

    /// Push the given bytes back into the buffer
    pub fn unread(&mut self, buf: &[u8]) {
        // Prepend buf bytes to what's in the buffer
        let mut concat = buf.to_vec();
        concat.append(&mut self.read_buf);
        self.read_buf = concat;
    }

    /// Try to receive an object from the stream. Consumes a full frame from the
    /// stream if available, otherwise nothing is consumed. Returns Ok if a full
    /// frame was available for consumption AND the bytes were derializable.
    pub fn try_recv<T: BorshDeserialize>(&mut self) -> std::io::Result<T> {
        // Number of bytes occupied by the length prefix
        const LEN_BYTES_LEN: usize = 4;
        // Buffer to hold the payload length bytes
        let mut len_bytes = [0u8; LEN_BYTES_LEN];
        // Finally read the length bytes, the method does all or nothing
        self.read_exact(&mut len_bytes)?;
        let len = u32::try_from_slice(&len_bytes)?;
        // Allocate a buffer to hold the payload
        let mut payload_bytes = vec![0u8; len as usize];
        // Read the payload, all or nothing
        if let Err(err) = self.read_exact(&mut payload_bytes) {
            // If there's an error reading the payload, then unread the payload
            self.unread(&len_bytes);
            // And propagate the given error
            Err(err)
        } else {
            // Finally, try to parse the actual payload
            T::try_from_slice(&payload_bytes)
        }
    }

    /// Attempt to write all the given bytes into the stream. Buffer the bytes
    /// which could not be written to the stream.
    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        // First extend the buffer with the input
        self.write_buf.extend_from_slice(buf);
        // Push the write buffer into the stream
        self.flush()
    }

    /// Attempt to push the write buffer into the stream. Error out with WouldBlock
    /// if the write buffer is not fully flushed
    pub fn flush(&mut self) -> std::io::Result<()> {
        // Then attempt to write the write buffer into the stream
        let bytes_written = self.stream.write(&self.write_buf)?;
        // Then finally remove the written bytes from the buffer
        self.write_buf.drain(..bytes_written);
        if self.write_buf.is_empty() {
            Ok(())
        } else if bytes_written == 0 {
            // If the write buffer still contains bytes, then this flush would block
            Err(std::io::ErrorKind::WouldBlock.into())
        } else {
            // Wrote some bytes but write buffer still non-empty, try again
            self.flush()
        }
    }

    /// Send the given object into the stream in a way such that it can be
    /// received with try_recv.
    pub fn send<T: BorshSerialize + Debug>(&mut self, t: T) -> std::io::Result<()> {
        // Convert the given object into bytes and then prepend a length
        // prefix. Write with write_all to ensure that bytes are not lost.
        self.write_all(&borsh::to_vec(&borsh::to_vec(&t)?)?)
    }
}

/// Commands sent from the client to the server over TCP.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum TcpRequest<BatchId, Node> {
    /// Push new batch of internal proofs
    PushInternalProofs(BatchId, Vec<Node>),
    /// Synchronize the worker
    Sync,
    /// Move the worker forward a step
    Step,
    /// Shutdown the worker
    Shutdown,
}

/// Updates sent from the server back to the client over TCP.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum TcpResponse<BatchId, Node> {
    /// Post new recursive proof
    RecursiveProof(BatchId, Node),
    /// Former number is the outer queue delta. Latter is new inner pending queue size.
    PendingQueueSize(usize, usize), // (delta, new_size)
    /// Update the proof throughput value
    ProofThroughput(f64),
}

/// An aggregator that forwards requests and responses over TCP
pub struct TcpStreamAggregator<BatchIds: Iterator, AggregatorIds: Iterator, Node>
where
    Node: BorshSerialize,
    BatchIds::Item: BorshSerialize,
{
    /// The stream used to communicate with the aggregator server
    pub stream: BufferedStream,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: AggregatorIds,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// The size of the inner queue of pending nodes
    pub inner_pending_queue_size: usize,
    /// The size of the outer queue of pending nodes
    pub outer_pending_queue_size: usize,
    /// The proofs processed per unit of time
    pub proof_throughput: f64,
    /// Queue of produced recursive proofs
    pub recursive_proofs: VecDeque<(BatchIds::Item, Node)>,
}

impl<BatchIds: Iterator, AggregatorIds: Iterator, Node>
    TcpStreamAggregator<BatchIds, AggregatorIds, Node>
where
    BatchIds::Item: Send + Hash + Eq + Copy + 'static + BorshSerialize + BorshDeserialize + Debug,
    AggregatorIds::Item: Send + Hash + Eq + Copy + 'static,
    Node: Send + 'static + BorshSerialize + BorshDeserialize + Debug,
{
    /// Connect to the aggregator server at the given address
    pub fn new<A: ToSocketAddrs>(
        free_batch_ids: BatchIds,
        free_aggregator_ids: AggregatorIds,
        addr: &A,
    ) -> Self {
        // Cnnect to the aggregator server
        let stream = TcpStream::connect(addr).expect("Failed to connect to Aggregator server");
        // This client uses nonblocking operations only
        stream
            .set_nonblocking(true)
            .expect("set_nonblocking call failed");

        Self {
            stream: BufferedStream::new(stream),
            free_batch_ids,
            free_aggregator_ids,
            inner_pending_queue_size: 0,
            outer_pending_queue_size: 0,
            proof_throughput: 1.0,
            recursive_proofs: VecDeque::new(),
        }
    }

    /// Send command to shutdown the server
    pub fn shutdown(&mut self) {
        self.stream
            .send(TcpRequest::<BatchIds::Item, Node>::Shutdown)
            .unwrap();
    }
}

// Implement the Aggregator trait for the client
impl<BatchIds: Iterator, AggregatorIds: Iterator, Node> Aggregator
    for TcpStreamAggregator<BatchIds, AggregatorIds, Node>
where
    BatchIds::Item: Send + Hash + Eq + Copy + 'static + BorshSerialize + BorshDeserialize + Debug,
    AggregatorIds::Item: Send + Hash + Eq + Copy + 'static,
    Node: Send + 'static + BorshSerialize + BorshDeserialize + Debug,
{
    type AggregatorId = AggregatorIds::Item;
    type BatchId = BatchIds::Item;
    type Node = Node;

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Node>) -> Self::BatchId {
        self.outer_pending_queue_size += proofs.len();
        let batch_id = gen_id(&mut self.free_batch_ids);
        if let Err(e) = self
            .stream
            .send(TcpRequest::PushInternalProofs(batch_id, proofs))
            && e.kind() != std::io::ErrorKind::WouldBlock
        {
            panic!("TcpStreamAggregator::push_internal_proofs error: {}", e);
        }
        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Node)> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        self.inner_pending_queue_size + self.outer_pending_queue_size
    }

    fn proof_throughput(&self) -> f64 {
        self.proof_throughput
    }

    fn step(&mut self) {
        if let Err(e) = self
            .stream
            .send(TcpRequest::<Self::BatchId, Self::Node>::Step)
            && e.kind() != std::io::ErrorKind::WouldBlock
        {
            panic!("TcpStreamAggregator::step error: {}", e);
        }
    }

    fn sync(&mut self) {
        // Update the object state with data from the inner thread
        while let Ok(resp) = self
            .stream
            .try_recv::<TcpResponse<Self::BatchId, Self::Node>>()
        {
            match resp {
                TcpResponse::PendingQueueSize(delta, new_size) => {
                    self.outer_pending_queue_size =
                        self.outer_pending_queue_size.saturating_sub(delta);
                    self.inner_pending_queue_size = new_size;
                }
                TcpResponse::ProofThroughput(throughput) => {
                    self.proof_throughput = throughput;
                }
                TcpResponse::RecursiveProof(batch_id, node) => {
                    self.recursive_proofs.push_back((batch_id, node));
                }
            }
        }
        // Command the inner aggregator to synchronize
        if let Err(e) = self
            .stream
            .send(TcpRequest::<Self::BatchId, Self::Node>::Sync)
            && e.kind() != std::io::ErrorKind::WouldBlock
        {
            panic!("TcpStreamAggregator::sync error: {}", e);
        }
    }

    fn insert_sub_aggregator(
        &mut self,
        _sub_aggregator: AggregatorBox<Self>,
    ) -> Self::AggregatorId {
        unimplemented!("TcpStreamAggregator does not support sub-aggregators.");
    }
    fn remove_sub_aggregator(&mut self, _id: &Self::AggregatorId) {
        unimplemented!("TcpStreamAggregator does not support sub-aggregators.");
    }
}

/// A TCP endpoint that forwards requests to an aggregator
pub struct TcpAggregatorServer<A: Aggregator> {
    /// The aggregator to which requests are forwarded
    pub aggregator: A,
    /// The TCP socket server that listens for requests
    pub listener: TcpListener,
}

impl<A: Aggregator> TcpAggregatorServer<A>
where
    A::BatchId: BorshSerialize + BorshDeserialize + Eq + Hash + Copy + Debug,
    A::Node: BorshSerialize + BorshDeserialize + Debug,
{
    /// Create an aggregator server that listens for requests at the given address
    /// and forwards them to the given aggregator
    pub fn new<B: ToSocketAddrs>(addr: &B, aggregator: A) -> Self {
        let listener = TcpListener::bind(addr).expect("Failed to bind to port");
        Self {
            aggregator,
            listener,
        }
    }

    /// Accept a connection and process the client's commands in a loop
    pub fn run(&mut self) -> std::io::Result<()> {
        println!("Server listening on {:?}", self.listener.local_addr());
        // Accept a new connection from the listener
        let (stream, peer_addr) = self.listener.accept()?;
        println!("Client connected from {:?}", peer_addr);
        // Wrap the stream so that received objects are automatically deserialized
        let mut stream = BufferedStream::new(stream);
        let mut batch_aliases = HashMap::new();
        // Process commands until the client disconnects or sends Shutdown
        while let Ok(req) = stream.try_recv::<TcpRequest<A::BatchId, A::Node>>() {
            // Number of internal proofs pushed during this iteration
            let mut internal_proofs_pushed = 0;
            // Forward the command to the inner aggregator
            match req {
                TcpRequest::PushInternalProofs(outer_id, proofs) => {
                    internal_proofs_pushed += proofs.len();
                    let inner_id = self.aggregator.push_internal_proofs(proofs);
                    batch_aliases.insert(inner_id, outer_id); // Map server ID to client ID
                }
                TcpRequest::Step => self.aggregator.step(),
                TcpRequest::Sync => self.aggregator.sync(),
                TcpRequest::Shutdown => break,
            }

            // Push generated proofs back to the client
            while let Some((inner_id, node)) = self.aggregator.pop_recursive_proof() {
                let outer_id = batch_aliases
                    .remove(&inner_id)
                    .expect("Unknown inner ID on server");
                stream
                    .send(TcpResponse::RecursiveProof(outer_id, node))
                    .expect("Unable to send back recursive proof");
            }

            // Keep client updated on load balancing metrics
            stream
                .send(TcpResponse::<A::BatchId, A::Node>::ProofThroughput(
                    self.aggregator.proof_throughput(),
                ))
                .expect("Unable to send back proof throughput");
            stream
                .send(TcpResponse::<A::BatchId, A::Node>::PendingQueueSize(
                    internal_proofs_pushed,
                    self.aggregator.pending_queue_size(),
                ))
                .expect("Unable to send back pending queue size");
        }
        println!("Client disconnected.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration;
    use crate::aggregator::TcpStreamAggregator;
    use crate::aggregator::MerkleAggregator;
    use std::thread;
    use std::sync::mpsc;
    use std::ops::RangeFrom;
    use nodes::init_srs;

    // A ZK proof to use for testing
    fn noir_recursive_no_zk_proof() -> VerifierInputs {
        // Constuct witnesses
        #[rustfmt::skip]
        let key_hash = vec![19, 181, 57, 172, 135, 10, 82, 33, 72, 158, 113, 161, 186, 183, 47, 125, 243, 247, 32, 168, 233, 101, 14, 95, 218, 240, 174, 90, 85, 20, 251, 132];
        #[rustfmt::skip]
        let proof: [[u8; 32]; 410] = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 108, 212, 34, 9, 100, 3, 151, 218, 212, 2, 58, 220, 177, 196, 212, 135], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 108, 142, 84, 194, 169, 244, 52, 64, 63, 120, 147, 44, 193, 152], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 56, 125, 218, 97, 157, 169, 110, 86, 46, 145, 207, 164, 68, 29, 60, 131], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 118, 241, 99, 170, 174, 193, 144, 19, 191, 155, 76, 223, 132, 137], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 176, 64, 6, 98, 175, 138, 200, 190, 3, 198, 54, 148, 187, 156, 122, 48], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 243, 72, 122, 92, 6, 112, 240, 180, 203, 248, 36, 240, 142, 7], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 238, 93, 15, 28, 111, 228, 160, 131, 226, 27, 234, 114, 120, 82, 100, 204, 89], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 67, 169, 172, 114, 0, 67, 220, 148, 25, 107, 127, 168, 80, 46], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 73, 127, 248, 61, 132, 185, 130, 194, 231, 81, 17, 19, 241, 148, 121, 67, 133], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 56, 199, 96, 155, 135, 35, 128, 194, 218, 114, 97, 149, 225, 102], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 101, 237, 173, 13, 206, 135, 59, 16, 73, 182, 166, 61, 155, 47, 114, 3], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 247, 136, 250, 231, 89, 119, 191, 25, 141, 242, 150, 5, 87, 94], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 54, 64, 126, 85, 28, 87, 63, 125, 181, 194, 118, 104, 98, 63, 85, 254], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 38, 246, 208, 0, 241, 19, 83, 45, 40, 195, 233, 223, 47, 16, 212], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 96, 169, 204, 224, 6, 61, 231, 153, 69, 144, 212, 139, 8, 212, 127, 172], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 85, 183, 137, 39, 0, 93, 86, 250, 135, 112, 168, 60, 138, 97], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 186, 58, 128, 188, 60, 198, 203, 43, 13, 228, 144, 97, 67, 242, 200, 47], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 176, 85, 214, 80, 213, 39, 22, 4, 203, 166, 157, 87, 195, 209], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 161, 204, 136, 91, 45, 17, 163, 249, 75, 204, 88, 244, 110, 60, 80, 44], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 68, 29, 215, 238, 231, 38, 199, 200, 238, 191, 209, 240, 255, 159], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 174, 161, 63, 169, 166, 244, 37, 102, 41, 191, 127, 174, 199, 73, 34, 52, 254], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 191, 240, 249, 248, 170, 137, 206, 190, 42, 162, 172, 217, 81, 99], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 70, 60, 236, 198, 11, 178, 207, 36, 111, 72, 0, 142, 69, 185, 153, 136], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 186, 124, 120, 71, 158, 72, 178, 17, 199, 12, 170, 150, 67, 164], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 237, 28, 252, 224, 184, 90, 112, 196, 22, 41, 164, 118, 81, 109, 192, 35, 158], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 113, 210, 248, 27, 211, 32, 31, 174, 155, 58, 48, 231, 221, 224], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 187, 151, 34, 43, 188, 112, 19, 197, 76, 98, 118, 5, 152, 255, 90, 212], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 83, 226, 127, 21, 99, 209, 186, 4, 221, 149, 48, 1, 132, 211], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 19, 162, 137, 136, 237, 210, 167, 119, 54, 215, 103, 13, 247, 192, 42, 179], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 248, 120, 201, 137, 9, 22, 173, 30, 186, 117, 181, 117, 42, 100], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 174, 251, 24, 86, 76, 97, 72, 248, 25, 74, 212, 219, 161, 51, 183, 87], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 38, 203, 50, 111, 6, 18, 38, 229, 101, 192, 132, 158, 15, 115, 204], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 25, 208, 133, 26, 111, 213, 56, 88, 34, 65, 57, 158, 83, 177, 64, 99], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 168, 254, 248, 53, 166, 159, 84, 154, 14, 10, 112, 180, 142, 230], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 72, 206, 139, 184, 228, 107, 81, 216, 215, 225, 166, 250, 234, 178, 191, 202], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 216, 33, 246, 151, 40, 207, 157, 18, 214, 65, 143, 52, 124, 169], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 168, 21, 204, 224, 190, 102, 0, 30, 255, 214, 154, 158, 35, 202, 210, 122, 178], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 5, 252, 47, 170, 226, 241, 141, 246, 174, 175, 177, 26, 85, 175], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 179, 44, 225, 61, 99, 69, 51, 62, 194, 85, 128, 128, 55, 52, 62, 224], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 221, 15, 57, 247, 56, 161, 204, 105, 229, 135, 229, 41, 135, 195], [31, 250, 235, 190, 80, 51, 173, 35, 96, 187, 5, 243, 92, 61, 60, 133, 117, 57, 243, 69, 21, 83, 37, 187, 108, 188, 147, 246, 196, 100, 243, 131], [16, 105, 98, 180, 144, 253, 243, 6, 87, 149, 63, 195, 37, 68, 27, 215, 178, 249, 245, 3, 100, 102, 74, 213, 215, 37, 97, 157, 43, 155, 12, 126], [34, 160, 130, 97, 20, 46, 118, 105, 104, 52, 88, 82, 81, 148, 33, 104, 240, 113, 160, 4, 200, 71, 124, 189, 154, 134, 28, 106, 228, 147, 129, 227], [15, 48, 54, 36, 113, 199, 165, 51, 156, 102, 31, 155, 252, 150, 218, 174, 155, 96, 74, 49, 250, 12, 179, 141, 114, 108, 159, 240, 96, 43, 133, 90], [2, 234, 152, 113, 54, 113, 60, 104, 45, 117, 191, 29, 166, 247, 208, 91, 110, 243, 192, 66, 86, 193, 176, 40, 145, 250, 225, 98, 196, 166, 61, 208], [44, 5, 39, 144, 182, 163, 172, 91, 25, 134, 140, 241, 79, 205, 193, 181, 13, 58, 141, 148, 89, 21, 45, 213, 176, 239, 210, 49, 116, 13, 254, 223], [40, 184, 94, 141, 142, 32, 18, 175, 12, 186, 185, 105, 97, 104, 177, 176, 56, 200, 87, 91, 206, 61, 16, 236, 233, 202, 49, 67, 210, 71, 20, 78], [21, 183, 91, 167, 37, 206, 236, 222, 195, 145, 121, 115, 179, 35, 181, 12, 151, 254, 176, 232, 12, 244, 116, 84, 63, 90, 19, 63, 251, 102, 110, 26], [20, 111, 214, 3, 133, 215, 245, 19, 65, 97, 11, 168, 218, 232, 32, 194, 156, 145, 163, 56, 60, 157, 114, 63, 25, 161, 102, 131, 138, 64, 113, 217], [3, 133, 172, 155, 114, 255, 26, 51, 130, 64, 165, 16, 239, 147, 251, 29, 124, 131, 101, 24, 18, 79, 233, 223, 71, 234, 221, 213, 180, 172, 77, 130], [5, 215, 177, 207, 61, 53, 127, 241, 34, 110, 13, 129, 53, 11, 209, 28, 244, 82, 210, 81, 153, 33, 246, 123, 146, 158, 21, 216, 14, 174, 96, 191], [12, 138, 78, 32, 222, 1, 138, 246, 63, 5, 173, 192, 58, 253, 236, 75, 70, 62, 149, 34, 98, 123, 226, 186, 39, 23, 95, 29, 68, 95, 156, 115], [42, 144, 170, 106, 168, 239, 221, 64, 45, 30, 76, 173, 243, 48, 165, 36, 110, 155, 230, 216, 243, 245, 190, 205, 197, 115, 254, 51, 92, 18, 59, 185], [17, 29, 21, 201, 210, 221, 7, 113, 68, 111, 105, 38, 64, 197, 249, 101, 188, 239, 51, 199, 8, 243, 220, 141, 84, 99, 129, 158, 211, 215, 238, 72], [38, 15, 175, 128, 55, 205, 235, 211, 38, 181, 24, 28, 166, 241, 246, 184, 162, 228, 151, 231, 151, 69, 212, 196, 3, 216, 102, 63, 222, 58, 99, 165], [26, 26, 200, 38, 140, 92, 61, 223, 153, 70, 117, 228, 129, 152, 41, 102, 162, 180, 233, 228, 174, 94, 68, 21, 64, 190, 126, 217, 182, 243, 199, 35], [45, 157, 4, 66, 60, 127, 156, 213, 135, 252, 183, 173, 207, 47, 168, 113, 107, 119, 208, 14, 148, 211, 82, 63, 229, 69, 224, 116, 110, 224, 41, 42], [2, 84, 3, 160, 184, 51, 83, 35, 152, 166, 94, 132, 39, 91, 109, 109, 86, 19, 19, 243, 11, 64, 211, 25, 15, 75, 175, 230, 77, 133, 43, 62], [12, 223, 40, 106, 151, 243, 199, 25, 39, 188, 179, 229, 66, 108, 222, 146, 179, 4, 224, 223, 162, 157, 247, 206, 64, 10, 117, 72, 248, 120, 166, 242], [35, 17, 116, 237, 228, 245, 188, 189, 231, 254, 242, 9, 189, 147, 188, 233, 92, 159, 89, 71, 42, 80, 238, 46, 15, 221, 83, 101, 113, 184, 222, 33], [28, 81, 51, 38, 237, 34, 193, 254, 118, 174, 71, 232, 227, 198, 84, 65, 211, 148, 151, 118, 219, 176, 46, 141, 170, 90, 121, 159, 177, 49, 1, 102], [17, 96, 174, 150, 60, 128, 5, 215, 192, 229, 53, 164, 159, 40, 190, 147, 223, 47, 165, 217, 104, 212, 148, 11, 244, 185, 57, 163, 59, 107, 193, 12], [13, 187, 51, 73, 143, 31, 122, 204, 138, 16, 119, 109, 207, 231, 86, 167, 120, 158, 224, 226, 168, 243, 110, 203, 215, 41, 232, 193, 214, 164, 221, 218], [19, 183, 88, 214, 216, 39, 204, 26, 117, 129, 99, 237, 111, 179, 200, 19, 123, 67, 30, 136, 11, 24, 50, 129, 99, 227, 216, 119, 120, 21, 48, 238], [21, 235, 53, 10, 40, 73, 169, 64, 92, 218, 98, 150, 55, 141, 2, 119, 37, 45, 180, 57, 204, 166, 93, 129, 181, 96, 181, 44, 2, 219, 223, 13], [8, 7, 33, 205, 123, 124, 139, 59, 91, 10, 148, 45, 97, 241, 20, 99, 89, 28, 4, 221, 143, 180, 140, 233, 252, 136, 16, 54, 163, 147, 168, 21], [19, 136, 211, 205, 13, 211, 14, 94, 173, 129, 128, 41, 17, 107, 158, 61, 46, 250, 23, 24, 52, 115, 41, 95, 148, 190, 31, 13, 151, 98, 54, 45], [28, 50, 178, 54, 200, 69, 131, 38, 251, 4, 209, 153, 146, 17, 81, 243, 155, 42, 30, 136, 78, 117, 23, 54, 56, 118, 156, 25, 32, 248, 228, 83], [3, 122, 243, 247, 121, 144, 229, 218, 155, 77, 212, 235, 40, 29, 68, 233, 186, 230, 112, 130, 18, 179, 123, 16, 214, 86, 11, 209, 162, 110, 147, 172], [45, 19, 157, 138, 203, 255, 199, 95, 246, 26, 156, 200, 155, 40, 235, 148, 141, 209, 230, 120, 136, 10, 104, 184, 3, 81, 96, 229, 239, 158, 38, 104], [16, 214, 78, 34, 94, 21, 119, 0, 162, 142, 128, 11, 161, 197, 125, 62, 217, 242, 119, 173, 147, 28, 248, 86, 54, 61, 2, 129, 146, 92, 238, 91], [39, 17, 242, 133, 10, 104, 191, 109, 195, 152, 230, 33, 191, 25, 2, 104, 89, 135, 124, 43, 198, 246, 124, 202, 76, 67, 13, 248, 62, 22, 150, 248], [9, 216, 219, 75, 206, 127, 161, 154, 216, 163, 115, 251, 39, 210, 179, 243, 239, 55, 13, 14, 10, 236, 247, 119, 10, 1, 29, 30, 167, 160, 70, 23], [19, 198, 202, 124, 252, 147, 27, 142, 247, 131, 49, 147, 134, 115, 160, 160, 72, 58, 172, 226, 236, 15, 61, 126, 51, 41, 53, 178, 228, 68, 155, 102], [38, 41, 165, 84, 235, 11, 111, 98, 213, 192, 61, 41, 201, 154, 200, 148, 14, 196, 18, 168, 113, 66, 251, 112, 199, 241, 34, 251, 116, 251, 198, 70], [36, 180, 99, 201, 116, 8, 68, 212, 248, 127, 130, 37, 72, 127, 231, 243, 12, 176, 13, 171, 107, 6, 188, 116, 172, 137, 81, 96, 138, 50, 203, 183], [5, 246, 47, 136, 131, 192, 173, 22, 53, 76, 114, 48, 6, 11, 250, 13, 53, 55, 236, 127, 192, 177, 242, 232, 213, 217, 233, 202, 42, 113, 30, 148], [30, 150, 114, 172, 20, 250, 196, 196, 12, 27, 128, 64, 91, 72, 15, 125, 134, 102, 96, 149, 253, 164, 135, 241, 134, 11, 22, 171, 210, 96, 1, 139], [30, 172, 213, 39, 57, 86, 34, 194, 131, 250, 91, 247, 120, 31, 126, 39, 116, 140, 181, 18, 180, 123, 124, 6, 197, 86, 222, 23, 155, 146, 163, 160], [23, 51, 217, 154, 75, 29, 191, 174, 251, 147, 46, 90, 59, 120, 106, 120, 179, 115, 83, 248, 150, 154, 160, 67, 61, 65, 96, 158, 191, 162, 85, 56], [28, 180, 247, 101, 211, 39, 100, 154, 50, 176, 53, 216, 146, 195, 50, 126, 51, 73, 172, 57, 135, 65, 149, 204, 249, 79, 154, 7, 230, 174, 73, 242], [22, 147, 251, 153, 220, 11, 74, 90, 38, 9, 232, 28, 55, 8, 77, 169, 189, 199, 10, 4, 127, 11, 233, 234, 64, 26, 251, 249, 110, 161, 214, 254], [38, 106, 122, 64, 192, 254, 236, 218, 220, 132, 247, 166, 210, 138, 126, 124, 190, 174, 112, 56, 190, 250, 6, 224, 162, 250, 200, 138, 17, 236, 230, 207], [38, 21, 20, 35, 208, 46, 216, 89, 60, 83, 43, 139, 171, 186, 139, 10, 251, 43, 30, 138, 77, 229, 237, 201, 199, 20, 240, 197, 104, 244, 53, 44], [43, 100, 225, 122, 246, 116, 139, 142, 3, 57, 5, 179, 15, 14, 212, 42, 31, 94, 245, 60, 126, 199, 85, 79, 2, 185, 21, 1, 45, 186, 205, 238], [42, 175, 210, 73, 219, 129, 156, 243, 105, 30, 11, 115, 121, 46, 77, 48, 250, 212, 144, 71, 197, 55, 160, 205, 253, 230, 57, 183, 32, 183, 99, 222], [13, 201, 2, 69, 46, 221, 86, 37, 210, 49, 203, 29, 175, 142, 128, 57, 166, 9, 180, 86, 71, 149, 167, 96, 23, 115, 108, 176, 150, 1, 178, 207], [35, 70, 140, 19, 70, 153, 57, 141, 203, 235, 198, 129, 129, 31, 195, 43, 215, 158, 93, 236, 228, 72, 19, 12, 178, 2, 177, 88, 110, 159, 71, 45], [0, 172, 74, 109, 242, 14, 227, 189, 162, 69, 22, 156, 144, 96, 128, 142, 179, 236, 144, 121, 253, 234, 190, 120, 163, 56, 246, 44, 231, 168, 157, 68], [8, 28, 69, 85, 66, 23, 127, 93, 52, 178, 73, 77, 186, 23, 50, 111, 143, 204, 27, 156, 190, 91, 148, 241, 216, 70, 23, 245, 183, 24, 28, 144], [37, 207, 14, 217, 148, 43, 172, 17, 233, 224, 169, 187, 3, 158, 103, 136, 10, 225, 253, 121, 107, 48, 98, 27, 120, 165, 50, 228, 243, 190, 29, 195], [3, 89, 98, 210, 119, 206, 56, 97, 49, 166, 143, 22, 96, 228, 244, 189, 61, 143, 198, 100, 73, 161, 6, 44, 222, 238, 212, 147, 112, 219, 74, 58], [48, 95, 41, 74, 184, 89, 203, 239, 106, 67, 86, 232, 129, 196, 20, 230, 48, 5, 184, 245, 102, 238, 8, 165, 231, 108, 28, 210, 201, 143, 38, 208], [2, 80, 196, 89, 69, 166, 245, 50, 180, 55, 204, 18, 252, 201, 132, 107, 189, 56, 92, 156, 177, 172, 61, 252, 141, 92, 58, 85, 153, 184, 125, 74], [0, 233, 7, 248, 131, 42, 15, 37, 159, 248, 212, 65, 251, 53, 83, 232, 79, 217, 63, 16, 98, 231, 9, 218, 63, 92, 167, 70, 248, 131, 249, 248], [24, 202, 136, 213, 116, 30, 27, 165, 123, 132, 229, 71, 235, 142, 255, 178, 251, 111, 236, 204, 37, 82, 113, 79, 146, 175, 116, 205, 99, 163, 89, 191], [38, 126, 102, 13, 87, 213, 167, 186, 235, 177, 194, 215, 153, 97, 139, 120, 168, 86, 53, 41, 68, 13, 229, 146, 96, 83, 178, 134, 214, 45, 185, 222], [30, 129, 232, 57, 66, 246, 225, 230, 19, 208, 100, 77, 19, 15, 20, 118, 63, 218, 157, 8, 51, 160, 252, 6, 56, 209, 235, 141, 183, 197, 202, 197], [8, 48, 245, 12, 173, 42, 14, 46, 168, 251, 198, 250, 37, 229, 201, 252, 96, 174, 28, 244, 247, 240, 63, 116, 209, 25, 90, 93, 215, 147, 199, 43], [22, 21, 10, 164, 54, 231, 220, 173, 87, 3, 91, 40, 128, 94, 12, 81, 16, 101, 206, 82, 24, 83, 165, 177, 120, 152, 67, 116, 33, 93, 90, 116], [0, 91, 181, 170, 19, 162, 109, 208, 70, 11, 139, 123, 67, 210, 123, 67, 176, 162, 58, 9, 23, 220, 99, 232, 195, 100, 146, 153, 57, 213, 250, 100], [3, 97, 107, 182, 4, 35, 223, 189, 205, 168, 132, 44, 189, 254, 207, 215, 159, 215, 172, 22, 45, 69, 227, 204, 228, 237, 66, 216, 182, 164, 94, 15], [10, 88, 124, 209, 43, 51, 8, 120, 68, 69, 144, 236, 116, 195, 7, 56, 8, 70, 15, 14, 27, 28, 10, 255, 230, 2, 165, 114, 37, 117, 197, 32], [32, 224, 249, 138, 142, 119, 54, 147, 11, 40, 0, 153, 211, 180, 174, 115, 3, 101, 95, 173, 223, 85, 146, 185, 197, 197, 223, 182, 241, 21, 24, 155], [26, 16, 87, 59, 129, 221, 248, 114, 17, 38, 9, 99, 98, 247, 192, 248, 157, 8, 67, 240, 41, 64, 51, 160, 224, 75, 123, 186, 96, 184, 117, 228], [12, 47, 152, 143, 205, 7, 243, 102, 13, 9, 13, 97, 18, 43, 193, 140, 171, 117, 93, 192, 55, 148, 43, 252, 203, 187, 205, 19, 154, 52, 32, 122], [19, 207, 27, 17, 206, 215, 191, 189, 96, 209, 104, 85, 151, 151, 229, 45, 10, 207, 107, 206, 113, 107, 63, 160, 235, 172, 1, 188, 119, 47, 38, 127], [38, 37, 240, 133, 138, 76, 68, 46, 208, 253, 133, 179, 209, 15, 82, 224, 27, 86, 148, 158, 141, 3, 5, 144, 115, 50, 113, 202, 8, 125, 142, 219], [34, 70, 84, 27, 188, 148, 86, 178, 28, 135, 176, 84, 35, 224, 143, 142, 223, 175, 253, 205, 179, 204, 84, 58, 122, 253, 242, 160, 242, 187, 89, 174], [46, 230, 220, 4, 89, 189, 123, 203, 72, 185, 253, 55, 223, 158, 164, 232, 243, 84, 85, 47, 61, 237, 143, 46, 131, 252, 213, 166, 209, 167, 9, 0], [29, 145, 17, 19, 35, 111, 7, 115, 31, 113, 155, 130, 136, 224, 149, 9, 140, 4, 127, 134, 198, 47, 2, 226, 164, 30, 80, 121, 170, 250, 89, 52], [6, 163, 253, 235, 182, 134, 147, 41, 28, 108, 196, 64, 9, 146, 82, 226, 201, 184, 145, 152, 36, 122, 128, 126, 169, 101, 38, 209, 238, 195, 127, 43], [44, 41, 84, 132, 38, 47, 55, 128, 50, 132, 189, 99, 21, 95, 255, 64, 210, 172, 86, 132, 222, 153, 209, 209, 55, 66, 196, 129, 97, 0, 50, 55], [10, 123, 115, 106, 70, 210, 245, 173, 206, 108, 174, 1, 214, 245, 64, 31, 74, 43, 152, 176, 1, 239, 158, 129, 108, 15, 157, 118, 86, 142, 87, 191], [7, 40, 101, 34, 173, 173, 128, 193, 173, 184, 123, 233, 141, 235, 24, 58, 81, 99, 103, 169, 252, 134, 168, 249, 241, 202, 46, 129, 175, 251, 219, 48], [15, 86, 96, 145, 18, 59, 203, 143, 119, 82, 35, 20, 255, 55, 146, 50, 194, 255, 54, 94, 46, 68, 6, 26, 111, 128, 25, 188, 193, 111, 27, 121], [18, 254, 90, 221, 120, 103, 118, 133, 87, 98, 195, 88, 153, 166, 35, 251, 42, 182, 56, 90, 54, 34, 50, 172, 188, 225, 13, 0, 27, 227, 248, 194], [42, 16, 32, 177, 146, 63, 166, 30, 196, 236, 111, 249, 238, 143, 221, 190, 152, 231, 7, 117, 83, 170, 228, 253, 31, 252, 199, 184, 24, 105, 29, 157], [31, 236, 218, 206, 240, 227, 60, 254, 218, 49, 212, 16, 215, 23, 131, 41, 2, 169, 88, 181, 160, 175, 149, 213, 97, 33, 250, 220, 193, 246, 252, 248], [39, 196, 49, 8, 35, 121, 89, 38, 154, 185, 98, 37, 242, 88, 64, 2, 144, 41, 11, 55, 29, 77, 253, 135, 72, 138, 32, 17, 54, 54, 91, 17], [2, 126, 208, 64, 132, 209, 157, 188, 50, 221, 61, 121, 31, 2, 24, 242, 230, 58, 38, 233, 79, 235, 131, 130, 181, 21, 89, 196, 85, 20, 247, 233], [40, 86, 196, 249, 83, 21, 248, 169, 41, 169, 162, 160, 254, 75, 171, 20, 6, 27, 40, 172, 200, 17, 14, 76, 8, 159, 218, 195, 162, 227, 190, 116], [43, 184, 2, 251, 231, 108, 172, 208, 92, 28, 187, 199, 240, 200, 91, 14, 205, 41, 126, 119, 14, 93, 106, 25, 208, 67, 204, 183, 30, 164, 114, 235], [24, 68, 178, 250, 75, 37, 65, 194, 111, 231, 19, 184, 126, 212, 202, 178, 14, 15, 237, 241, 0, 180, 65, 235, 73, 37, 125, 30, 26, 99, 160, 123], [38, 184, 183, 139, 166, 222, 11, 248, 42, 107, 123, 215, 78, 225, 2, 76, 102, 255, 166, 91, 127, 21, 197, 127, 45, 216, 8, 60, 156, 57, 109, 31], [14, 30, 20, 19, 192, 92, 21, 224, 227, 130, 131, 140, 123, 146, 55, 146, 46, 1, 217, 139, 55, 20, 142, 2, 123, 77, 187, 155, 92, 13, 232, 161], [17, 31, 170, 229, 190, 45, 57, 109, 173, 120, 75, 137, 67, 87, 42, 205, 53, 181, 68, 255, 199, 207, 161, 232, 8, 159, 182, 178, 223, 161, 127, 133], [20, 146, 222, 156, 118, 108, 14, 2, 227, 196, 133, 102, 219, 158, 223, 87, 37, 121, 119, 144, 174, 153, 178, 160, 68, 171, 61, 202, 32, 252, 117, 178], [43, 71, 199, 86, 110, 118, 239, 143, 66, 16, 201, 189, 22, 224, 60, 253, 161, 159, 62, 79, 244, 231, 74, 137, 2, 205, 7, 137, 51, 36, 89, 177], [13, 236, 56, 152, 18, 112, 211, 167, 53, 137, 42, 17, 194, 97, 184, 156, 44, 246, 33, 72, 224, 97, 79, 145, 9, 165, 28, 119, 171, 21, 186, 255], [12, 223, 178, 100, 140, 130, 72, 131, 238, 52, 25, 116, 27, 121, 164, 18, 242, 66, 9, 43, 150, 144, 133, 164, 242, 152, 105, 7, 36, 70, 83, 55], [16, 22, 124, 79, 132, 4, 157, 1, 36, 71, 214, 44, 14, 80, 56, 79, 13, 157, 232, 122, 103, 121, 59, 219, 236, 216, 200, 189, 131, 72, 70, 61], [33, 113, 237, 117, 19, 187, 156, 20, 101, 2, 62, 29, 165, 234, 126, 201, 178, 124, 220, 252, 33, 240, 255, 173, 52, 120, 10, 172, 182, 147, 100, 127], [30, 165, 53, 94, 66, 248, 87, 129, 202, 14, 29, 112, 20, 34, 49, 149, 110, 21, 91, 175, 0, 71, 28, 53, 172, 106, 175, 255, 25, 211, 90, 59], [29, 227, 209, 51, 11, 238, 201, 39, 230, 82, 79, 220, 7, 50, 255, 73, 20, 243, 28, 92, 193, 58, 0, 195, 149, 133, 62, 10, 99, 201, 64, 72], [27, 5, 221, 75, 12, 60, 177, 57, 153, 234, 249, 177, 109, 237, 85, 116, 35, 147, 93, 55, 145, 38, 32, 209, 254, 71, 217, 203, 115, 143, 203, 255], [17, 50, 182, 9, 234, 55, 201, 194, 187, 199, 187, 14, 29, 61, 178, 165, 194, 201, 178, 71, 233, 51, 239, 68, 43, 245, 51, 198, 16, 65, 105, 71], [46, 82, 240, 73, 107, 20, 204, 253, 250, 227, 238, 239, 24, 80, 176, 77, 56, 255, 113, 161, 95, 56, 62, 2, 168, 181, 47, 62, 55, 196, 6, 19], [41, 67, 41, 9, 80, 120, 7, 126, 90, 162, 171, 106, 117, 149, 157, 48, 170, 137, 130, 163, 247, 50, 194, 213, 215, 4, 99, 26, 91, 55, 158, 172], [24, 164, 207, 204, 52, 153, 82, 68, 166, 182, 53, 3, 52, 254, 201, 192, 223, 45, 63, 56, 0, 71, 176, 253, 215, 120, 24, 177, 28, 82, 217, 247], [13, 5, 209, 11, 232, 124, 18, 187, 92, 213, 108, 69, 238, 70, 183, 38, 103, 171, 227, 26, 107, 57, 74, 109, 114, 144, 56, 171, 93, 130, 63, 32], [11, 188, 206, 35, 73, 99, 246, 209, 176, 98, 109, 143, 197, 158, 102, 237, 67, 98, 199, 62, 134, 238, 156, 73, 183, 106, 176, 140, 109, 18, 115, 39], [13, 156, 235, 217, 236, 83, 134, 100, 84, 102, 81, 81, 202, 4, 194, 85, 132, 92, 107, 202, 1, 155, 215, 77, 70, 38, 59, 67, 139, 190, 89, 142], [6, 30, 57, 240, 157, 35, 18, 31, 116, 99, 39, 199, 195, 129, 203, 107, 145, 131, 251, 151, 31, 59, 226, 78, 13, 253, 92, 203, 224, 255, 63, 72], [12, 231, 50, 34, 116, 24, 233, 34, 174, 109, 191, 152, 59, 40, 160, 170, 249, 49, 132, 162, 7, 139, 97, 171, 95, 161, 19, 42, 92, 57, 4, 215], [42, 181, 188, 42, 212, 172, 97, 182, 182, 71, 123, 187, 100, 251, 115, 230, 52, 122, 98, 22, 82, 49, 205, 200, 208, 188, 40, 119, 195, 216, 98, 98], [24, 241, 244, 5, 129, 135, 251, 146, 94, 56, 183, 135, 5, 37, 245, 179, 190, 79, 54, 178, 201, 35, 73, 161, 47, 223, 216, 38, 42, 69, 189, 13], [42, 235, 18, 132, 28, 110, 201, 236, 118, 170, 218, 239, 42, 70, 87, 86, 166, 207, 253, 114, 25, 53, 80, 100, 124, 137, 203, 94, 172, 218, 212, 12], [17, 38, 94, 121, 65, 52, 244, 209, 144, 114, 34, 239, 97, 202, 114, 177, 98, 41, 170, 103, 245, 151, 23, 149, 167, 182, 15, 119, 119, 48, 225, 252], [35, 237, 38, 166, 223, 58, 116, 237, 85, 40, 89, 238, 103, 182, 89, 154, 246, 180, 150, 251, 81, 6, 65, 123, 118, 182, 140, 30, 96, 188, 163, 2], [33, 70, 133, 111, 231, 23, 167, 120, 101, 183, 1, 6, 20, 37, 36, 228, 220, 94, 62, 92, 124, 136, 54, 140, 11, 101, 7, 194, 69, 138, 158, 237], [41, 2, 151, 31, 130, 128, 3, 121, 247, 198, 183, 37, 200, 169, 199, 111, 157, 65, 202, 25, 48, 88, 232, 4, 92, 29, 65, 195, 123, 31, 195, 32], [28, 182, 244, 20, 177, 20, 89, 32, 112, 42, 245, 151, 227, 216, 101, 12, 94, 255, 160, 217, 46, 146, 146, 116, 164, 237, 22, 140, 208, 105, 215, 131], [30, 10, 41, 225, 189, 144, 200, 24, 68, 175, 20, 137, 39, 41, 78, 62, 244, 154, 121, 115, 53, 43, 120, 69, 73, 23, 250, 116, 30, 187, 72, 166], [22, 23, 78, 176, 255, 120, 158, 60, 21, 245, 132, 18, 120, 96, 2, 29, 101, 193, 159, 8, 6, 176, 218, 250, 163, 211, 8, 17, 175, 77, 243, 91], [34, 54, 180, 122, 188, 36, 53, 235, 80, 37, 170, 91, 194, 241, 254, 96, 42, 140, 121, 94, 85, 39, 87, 117, 16, 77, 127, 104, 161, 44, 75, 129], [9, 225, 255, 9, 69, 162, 20, 131, 254, 185, 250, 140, 111, 42, 80, 14, 4, 206, 9, 152, 170, 220, 201, 145, 35, 92, 215, 81, 79, 227, 44, 47], [36, 169, 181, 30, 204, 156, 12, 55, 94, 193, 106, 219, 55, 199, 246, 193, 92, 90, 140, 105, 29, 37, 44, 32, 43, 141, 202, 125, 15, 198, 229, 120], [38, 232, 190, 121, 250, 216, 166, 167, 81, 162, 106, 80, 175, 169, 132, 61, 241, 186, 187, 201, 110, 79, 128, 70, 231, 127, 31, 21, 139, 231, 65, 84], [16, 70, 50, 33, 63, 41, 29, 132, 229, 99, 62, 140, 38, 182, 51, 227, 11, 210, 26, 122, 33, 103, 242, 15, 133, 168, 15, 150, 22, 154, 197, 73], [30, 142, 135, 100, 136, 136, 220, 68, 174, 178, 12, 194, 218, 74, 94, 249, 115, 68, 0, 114, 75, 213, 49, 45, 193, 228, 69, 130, 102, 213, 231, 119], [36, 149, 141, 52, 31, 205, 251, 13, 149, 115, 93, 229, 185, 56, 227, 13, 13, 200, 140, 12, 192, 46, 205, 7, 132, 115, 137, 88, 11, 202, 121, 172], [20, 180, 65, 127, 222, 25, 128, 188, 255, 100, 97, 179, 188, 28, 152, 232, 142, 35, 142, 122, 32, 60, 150, 166, 166, 7, 193, 139, 90, 208, 153, 51], [46, 66, 196, 187, 94, 233, 239, 16, 127, 102, 249, 123, 218, 190, 77, 35, 62, 13, 134, 47, 223, 189, 17, 142, 223, 74, 94, 84, 121, 236, 83, 218], [15, 93, 119, 95, 39, 132, 155, 89, 196, 45, 5, 144, 61, 123, 244, 0, 227, 158, 244, 193, 222, 86, 219, 35, 214, 188, 92, 24, 107, 196, 208, 243], [24, 253, 161, 121, 114, 143, 69, 122, 186, 171, 248, 98, 27, 190, 114, 252, 106, 177, 163, 192, 55, 61, 199, 177, 247, 147, 38, 210, 178, 44, 69, 27], [44, 213, 228, 105, 12, 254, 73, 117, 121, 183, 145, 210, 169, 135, 195, 239, 183, 63, 99, 143, 148, 4, 160, 48, 77, 87, 114, 205, 68, 76, 187, 30], [25, 46, 23, 2, 125, 125, 182, 120, 213, 60, 238, 253, 102, 117, 97, 86, 235, 243, 246, 92, 144, 192, 167, 21, 25, 33, 200, 190, 34, 129, 157, 152], [12, 99, 35, 3, 159, 16, 177, 173, 15, 90, 220, 205, 239, 101, 225, 230, 77, 203, 252, 114, 36, 121, 244, 232, 152, 66, 215, 109, 97, 132, 80, 22], [13, 154, 21, 116, 141, 107, 198, 57, 251, 167, 105, 197, 192, 247, 198, 175, 96, 158, 52, 92, 16, 127, 155, 23, 227, 252, 12, 44, 239, 129, 99, 134], [22, 144, 138, 123, 213, 99, 94, 3, 126, 171, 217, 116, 76, 81, 16, 217, 8, 72, 163, 62, 233, 182, 57, 11, 248, 41, 221, 13, 24, 153, 81, 37], [44, 156, 52, 234, 181, 166, 37, 103, 35, 60, 150, 93, 37, 165, 184, 204, 116, 70, 236, 116, 254, 247, 187, 60, 131, 21, 245, 127, 19, 148, 134, 69], [8, 49, 40, 44, 106, 255, 63, 243, 252, 109, 26, 46, 93, 118, 10, 56, 222, 218, 201, 69, 178, 150, 218, 40, 20, 139, 212, 23, 223, 100, 152, 101], [18, 163, 173, 174, 56, 234, 127, 199, 236, 161, 87, 117, 140, 188, 246, 114, 149, 21, 125, 140, 179, 112, 168, 90, 181, 56, 92, 174, 164, 182, 207, 191], [12, 140, 239, 253, 240, 41, 182, 110, 248, 112, 134, 211, 250, 206, 125, 236, 217, 140, 38, 75, 111, 161, 241, 76, 238, 230, 113, 39, 239, 26, 124, 208], [14, 175, 98, 52, 197, 47, 100, 97, 34, 31, 42, 31, 141, 81, 112, 162, 148, 75, 250, 136, 42, 128, 175, 251, 134, 11, 27, 255, 203, 87, 4, 219], [6, 36, 94, 60, 13, 56, 17, 72, 3, 214, 76, 28, 121, 235, 219, 11, 74, 111, 223, 241, 100, 206, 19, 231, 41, 88, 65, 141, 44, 96, 140, 172], [1, 226, 6, 55, 35, 228, 78, 167, 146, 42, 141, 99, 177, 25, 100, 187, 251, 214, 88, 168, 3, 143, 125, 158, 89, 219, 106, 11, 172, 82, 106, 52], [10, 29, 64, 124, 101, 38, 2, 205, 92, 141, 15, 196, 195, 8, 19, 34, 121, 199, 74, 77, 210, 98, 40, 174, 175, 39, 51, 174, 47, 12, 47, 96], [20, 169, 30, 135, 161, 178, 244, 153, 212, 103, 56, 143, 189, 189, 236, 89, 165, 83, 59, 224, 87, 151, 175, 253, 241, 221, 249, 37, 238, 5, 182, 64], [38, 183, 166, 96, 144, 227, 88, 185, 145, 142, 126, 147, 20, 194, 206, 113, 103, 53, 157, 15, 166, 141, 82, 110, 175, 83, 3, 99, 247, 80, 216, 99], [3, 102, 227, 74, 144, 100, 63, 93, 79, 12, 79, 248, 143, 125, 47, 39, 42, 105, 145, 24, 66, 69, 236, 232, 153, 18, 229, 161, 225, 193, 171, 45], [9, 0, 116, 0, 47, 1, 108, 4, 104, 250, 114, 234, 211, 78, 15, 176, 80, 135, 254, 115, 25, 254, 219, 146, 138, 154, 22, 12, 94, 175, 211, 11], [3, 225, 219, 174, 6, 54, 48, 241, 230, 47, 148, 34, 128, 170, 150, 121, 3, 15, 82, 141, 7, 118, 60, 122, 48, 173, 151, 232, 15, 113, 16, 227], [18, 49, 185, 94, 65, 62, 165, 42, 35, 117, 18, 169, 150, 45, 237, 102, 68, 135, 112, 65, 138, 59, 184, 242, 91, 203, 14, 6, 164, 39, 59, 82], [11, 17, 139, 41, 42, 164, 31, 148, 87, 158, 59, 254, 193, 111, 132, 207, 167, 183, 50, 201, 236, 244, 140, 51, 73, 14, 242, 177, 82, 51, 195, 64], [12, 201, 159, 39, 194, 242, 248, 173, 54, 125, 132, 55, 126, 43, 140, 197, 212, 74, 150, 81, 63, 231, 49, 193, 97, 61, 134, 126, 95, 23, 59, 164], [25, 131, 100, 158, 149, 63, 140, 93, 183, 223, 108, 150, 145, 114, 13, 198, 55, 27, 8, 122, 87, 232, 244, 75, 233, 188, 198, 250, 230, 41, 156, 152], [2, 156, 252, 205, 1, 217, 47, 55, 126, 200, 168, 97, 223, 210, 161, 103, 112, 69, 132, 53, 170, 110, 167, 110, 152, 90, 252, 111, 129, 205, 216, 42], [19, 181, 154, 188, 60, 132, 66, 140, 216, 49, 13, 205, 253, 36, 99, 66, 229, 119, 158, 47, 119, 224, 107, 86, 215, 194, 163, 238, 168, 189, 171, 179], [24, 17, 83, 182, 144, 83, 63, 81, 10, 44, 229, 175, 42, 33, 76, 60, 10, 227, 199, 71, 203, 140, 126, 58, 35, 160, 38, 11, 110, 212, 120, 74], [12, 217, 203, 79, 2, 174, 15, 74, 197, 49, 51, 236, 225, 88, 220, 115, 223, 147, 39, 237, 97, 31, 70, 167, 95, 219, 246, 40, 91, 46, 26, 36], [0, 229, 67, 172, 114, 183, 241, 51, 142, 251, 110, 10, 141, 33, 144, 99, 249, 187, 254, 121, 75, 168, 239, 46, 122, 217, 222, 133, 155, 240, 205, 122], [3, 107, 111, 178, 37, 229, 149, 249, 249, 4, 99, 151, 229, 180, 43, 242, 208, 127, 80, 198, 12, 254, 200, 116, 49, 234, 243, 253, 92, 138, 82, 74], [32, 150, 22, 241, 17, 33, 101, 190, 65, 169, 216, 220, 7, 112, 142, 212, 126, 177, 185, 189, 51, 132, 115, 143, 200, 246, 56, 18, 251, 234, 241, 58], [38, 27, 168, 224, 121, 115, 136, 191, 147, 24, 85, 197, 100, 107, 129, 225, 133, 200, 220, 161, 136, 246, 105, 77, 141, 153, 40, 152, 208, 146, 146, 242], [14, 16, 217, 197, 173, 218, 25, 239, 223, 165, 1, 104, 199, 157, 104, 200, 207, 183, 232, 138, 154, 111, 153, 76, 170, 37, 215, 127, 41, 181, 59, 87], [5, 21, 72, 214, 104, 221, 42, 30, 234, 22, 186, 86, 164, 139, 130, 248, 37, 209, 50, 101, 218, 204, 11, 220, 147, 133, 15, 186, 162, 71, 36, 179], [35, 194, 220, 136, 46, 208, 165, 64, 242, 1, 41, 180, 115, 132, 184, 56, 68, 113, 23, 0, 131, 88, 129, 65, 239, 37, 17, 157, 19, 74, 151, 131], [41, 187, 78, 110, 12, 124, 199, 87, 167, 74, 66, 192, 202, 225, 80, 127, 120, 229, 73, 100, 60, 79, 39, 5, 198, 147, 227, 72, 18, 181, 159, 196], [13, 195, 75, 53, 236, 121, 226, 44, 136, 43, 159, 150, 87, 6, 66, 110, 190, 240, 47, 0, 113, 74, 122, 10, 78, 29, 122, 71, 231, 3, 134, 250], [13, 25, 154, 8, 224, 150, 67, 102, 29, 253, 77, 209, 210, 253, 163, 242, 157, 47, 20, 43, 72, 145, 117, 123, 22, 155, 73, 17, 108, 231, 227, 213], [18, 158, 229, 72, 179, 232, 167, 91, 41, 177, 37, 124, 48, 51, 115, 155, 114, 106, 113, 128, 210, 166, 128, 225, 51, 230, 183, 171, 168, 233, 30, 87], [5, 85, 61, 96, 45, 151, 136, 55, 81, 118, 86, 75, 200, 132, 99, 162, 147, 78, 205, 11, 77, 213, 129, 107, 24, 235, 229, 238, 180, 143, 152, 153], [18, 81, 45, 166, 140, 53, 57, 151, 35, 181, 130, 89, 11, 80, 114, 135, 229, 241, 134, 4, 155, 158, 161, 83, 90, 9, 65, 145, 242, 221, 209, 25], [23, 51, 55, 64, 188, 225, 175, 16, 135, 48, 181, 204, 123, 144, 152, 57, 4, 144, 181, 8, 45, 4, 157, 227, 54, 104, 58, 9, 78, 68, 167, 66], [9, 55, 40, 87, 53, 120, 215, 134, 172, 133, 77, 174, 38, 189, 181, 160, 247, 48, 71, 2, 172, 59, 77, 27, 248, 152, 69, 66, 118, 247, 58, 108], [31, 72, 87, 137, 203, 60, 155, 242, 81, 16, 138, 50, 78, 212, 111, 19, 49, 36, 209, 194, 230, 169, 89, 197, 118, 2, 185, 84, 254, 134, 91, 116], [3, 202, 159, 121, 70, 9, 183, 33, 174, 153, 209, 129, 120, 112, 182, 92, 18, 234, 124, 90, 219, 166, 220, 64, 61, 72, 147, 146, 186, 179, 78, 98], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [1, 70, 255, 97, 39, 135, 73, 222, 175, 70, 232, 16, 34, 29, 10, 190, 11, 72, 231, 165, 242, 245, 2, 77, 173, 78, 105, 216, 42, 182, 32, 110], [13, 166, 175, 229, 221, 254, 59, 77, 157, 5, 208, 62, 6, 183, 226, 227, 122, 10, 82, 131, 221, 185, 179, 129, 233, 127, 90, 220, 144, 236, 192, 123], [40, 43, 17, 46, 8, 197, 128, 107, 219, 143, 180, 161, 0, 105, 132, 70, 115, 139, 134, 129, 26, 112, 21, 248, 157, 161, 161, 183, 56, 177, 227, 213], [14, 93, 149, 91, 129, 139, 154, 48, 189, 244, 88, 224, 95, 113, 239, 113, 240, 91, 83, 249, 74, 158, 4, 87, 118, 236, 35, 18, 212, 34, 29, 220], [5, 192, 84, 67, 236, 146, 76, 213, 135, 120, 206, 226, 244, 28, 245, 231, 216, 132, 88, 208, 66, 131, 84, 207, 212, 136, 121, 207, 61, 39, 184, 23], [43, 46, 131, 137, 20, 184, 98, 145, 53, 252, 31, 80, 245, 72, 221, 59, 67, 89, 159, 173, 67, 193, 189, 111, 24, 13, 232, 214, 31, 101, 242, 26], [42, 39, 82, 72, 225, 5, 12, 145, 59, 247, 133, 79, 203, 30, 194, 27, 171, 58, 173, 14, 1, 40, 45, 205, 18, 57, 38, 51, 93, 4, 215, 216], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [9, 204, 212, 175, 67, 40, 98, 114, 242, 59, 12, 10, 179, 27, 106, 91, 11, 153, 207, 127, 236, 244, 105, 49, 143, 29, 123, 121, 250, 150, 7, 212], [16, 98, 0, 156, 115, 48, 80, 4, 52, 67, 77, 230, 121, 210, 128, 65, 161, 212, 201, 228, 145, 222, 41, 45, 154, 73, 144, 109, 212, 128, 105, 16], [19, 97, 51, 254, 141, 118, 174, 200, 69, 78, 150, 19, 54, 193, 239, 17, 219, 196, 0, 15, 173, 133, 126, 13, 163, 7, 61, 38, 32, 204, 142, 138], [35, 240, 160, 204, 56, 199, 83, 125, 72, 34, 102, 115, 108, 90, 58, 133, 127, 217, 200, 110, 56, 249, 156, 31, 20, 162, 194, 130, 9, 5, 128, 50], [11, 6, 212, 71, 64, 151, 49, 223, 106, 32, 105, 111, 154, 189, 141, 66, 61, 81, 163, 159, 236, 246, 60, 34, 97, 2, 186, 177, 201, 25, 126, 118], [11, 141, 3, 46, 39, 156, 156, 221, 158, 225, 63, 182, 134, 73, 175, 62, 51, 124, 221, 136, 161, 83, 23, 223, 80, 35, 44, 151, 156, 36, 71, 107], [41, 8, 107, 124, 140, 155, 156, 76, 147, 163, 128, 80, 82, 181, 1, 17, 110, 99, 66, 61, 9, 243, 165, 202, 224, 102, 26, 189, 63, 253, 166, 247], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [39, 177, 130, 149, 74, 155, 85, 252, 140, 47, 114, 48, 180, 102, 81, 255, 236, 106, 88, 176, 182, 165, 8, 173, 202, 117, 158, 50, 43, 145, 207, 155], [11, 245, 92, 169, 115, 229, 218, 63, 98, 215, 242, 215, 177, 150, 124, 175, 70, 93, 199, 235, 216, 201, 64, 156, 228, 127, 22, 41, 55, 57, 241, 119], [4, 213, 239, 162, 107, 54, 101, 113, 115, 209, 206, 84, 63, 225, 8, 134, 3, 112, 231, 205, 45, 241, 0, 180, 65, 50, 207, 71, 186, 114, 62, 215], [17, 4, 191, 103, 195, 158, 236, 24, 164, 108, 61, 27, 185, 228, 249, 96, 135, 52, 158, 80, 215, 127, 235, 57, 67, 199, 80, 213, 201, 89, 166, 29], [30, 1, 27, 120, 236, 213, 141, 18, 174, 1, 89, 255, 221, 169, 194, 112, 60, 120, 198, 33, 43, 181, 181, 74, 86, 16, 53, 104, 20, 42, 220, 56], [7, 84, 68, 49, 178, 254, 161, 170, 220, 132, 197, 77, 230, 35, 7, 212, 219, 244, 167, 49, 119, 119, 18, 159, 224, 234, 41, 62, 63, 22, 159, 229], [5, 212, 66, 44, 124, 122, 221, 208, 203, 69, 207, 110, 70, 176, 184, 216, 8, 254, 141, 232, 198, 157, 133, 155, 129, 185, 84, 168, 119, 155, 22, 6], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [28, 206, 108, 98, 14, 100, 153, 13, 116, 90, 22, 45, 171, 226, 236, 132, 187, 191, 129, 141, 180, 95, 165, 164, 241, 109, 99, 159, 170, 80, 205, 122], [4, 0, 236, 48, 143, 243, 24, 213, 4, 220, 119, 116, 110, 156, 245, 18, 140, 207, 203, 68, 206, 211, 36, 160, 174, 245, 39, 110, 76, 234, 14, 181], [32, 168, 59, 131, 103, 27, 239, 34, 130, 60, 159, 73, 158, 191, 27, 8, 20, 98, 1, 208, 86, 204, 129, 27, 186, 38, 67, 96, 3, 128, 74, 153], [39, 136, 65, 247, 79, 178, 78, 184, 4, 212, 219, 229, 157, 14, 136, 118, 153, 165, 160, 22, 252, 41, 125, 129, 67, 156, 57, 195, 81, 218, 175, 9], [19, 254, 101, 84, 21, 34, 191, 160, 122, 113, 251, 66, 47, 179, 126, 128, 216, 193, 171, 117, 71, 87, 241, 252, 36, 98, 3, 178, 234, 155, 153, 238], [41, 89, 100, 92, 199, 88, 86, 19, 161, 129, 11, 169, 236, 46, 238, 96, 192, 51, 171, 93, 99, 212, 171, 153, 178, 198, 163, 202, 5, 77, 83, 56], [8, 182, 47, 136, 85, 212, 16, 192, 104, 212, 162, 37, 74, 247, 216, 195, 22, 1, 129, 225, 1, 9, 84, 124, 108, 147, 231, 111, 224, 232, 175, 27], [37, 197, 19, 83, 89, 47, 93, 249, 76, 94, 106, 166, 245, 61, 179, 240, 43, 4, 126, 164, 241, 227, 134, 122, 188, 109, 173, 38, 43, 16, 195, 217], [43, 42, 86, 223, 11, 228, 226, 76, 50, 186, 55, 132, 12, 80, 90, 171, 166, 209, 21, 5, 61, 111, 183, 90, 244, 167, 91, 71, 144, 60, 230, 9], [24, 168, 5, 204, 229, 238, 0, 53, 76, 196, 216, 173, 97, 26, 82, 237, 213, 2, 93, 84, 219, 253, 106, 226, 223, 69, 6, 112, 45, 206, 179, 252], [42, 128, 224, 245, 108, 171, 239, 61, 220, 85, 216, 188, 171, 210, 167, 218, 59, 214, 202, 162, 196, 219, 171, 48, 202, 166, 252, 172, 82, 204, 173, 180], [45, 24, 161, 79, 194, 66, 248, 91, 190, 40, 3, 137, 92, 94, 244, 153, 77, 40, 76, 159, 74, 49, 112, 83, 15, 191, 165, 130, 55, 20, 105, 105], [0, 79, 243, 89, 225, 129, 106, 230, 193, 241, 54, 6, 79, 217, 83, 39, 34, 249, 147, 147, 27, 32, 26, 96, 156, 184, 46, 237, 86, 236, 38, 226], [5, 38, 182, 32, 191, 180, 150, 169, 194, 80, 42, 210, 182, 224, 85, 207, 196, 196, 50, 55, 7, 170, 19, 137, 131, 81, 25, 16, 24, 229, 4, 164], [14, 254, 150, 39, 172, 167, 148, 234, 227, 148, 143, 168, 121, 10, 203, 118, 216, 202, 252, 19, 177, 203, 196, 208, 52, 166, 200, 93, 10, 166, 155, 118], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 225, 99, 31, 143, 125, 109, 246, 131, 49, 83, 225, 84, 101, 186, 115, 84, 165, 105, 162, 12, 234, 33, 43, 120, 151, 216, 17, 39, 146, 160, 137], [37, 64, 42, 5, 160, 7, 98, 7, 224, 93, 128, 172, 153, 127, 67, 95, 244, 136, 20, 152, 70, 29, 56, 33, 79, 219, 200, 51, 149, 205, 199, 77], [20, 130, 194, 101, 80, 138, 110, 57, 239, 138, 57, 127, 44, 49, 74, 191, 38, 184, 210, 155, 17, 27, 102, 17, 179, 94, 255, 139, 9, 68, 198, 218], [5, 163, 194, 74, 225, 24, 127, 16, 154, 162, 118, 109, 198, 234, 39, 28, 58, 93, 237, 217, 160, 143, 251, 94, 42, 217, 192, 37, 162, 11, 255, 167], [37, 172, 196, 94, 147, 176, 102, 200, 227, 87, 85, 170, 199, 38, 33, 42, 223, 48, 13, 110, 122, 248, 247, 188, 113, 126, 144, 152, 248, 251, 146, 79], [42, 64, 85, 80, 26, 150, 49, 15, 211, 159, 17, 34, 241, 174, 66, 184, 4, 12, 203, 105, 55, 197, 105, 182, 250, 43, 176, 60, 44, 62, 199, 192], [41, 142, 25, 53, 15, 215, 42, 165, 152, 196, 219, 42, 213, 73, 146, 44, 44, 232, 56, 75, 68, 70, 75, 115, 137, 37, 37, 173, 255, 168, 192, 156], [4, 114, 126, 64, 190, 201, 208, 113, 39, 255, 108, 190, 109, 54, 210, 168, 137, 0, 10, 218, 113, 230, 124, 102, 40, 168, 205, 215, 90, 168, 229, 125], [32, 225, 5, 193, 27, 39, 196, 22, 191, 6, 164, 61, 16, 86, 83, 253, 217, 162, 105, 208, 191, 39, 176, 37, 72, 148, 53, 173, 106, 55, 191, 100], [4, 207, 71, 125, 128, 125, 9, 26, 42, 97, 73, 28, 141, 251, 142, 126, 96, 126, 141, 197, 50, 204, 235, 115, 52, 254, 66, 207, 255, 151, 14, 169], [35, 123, 144, 236, 240, 91, 232, 78, 140, 247, 29, 74, 185, 103, 124, 125, 112, 105, 79, 189, 174, 127, 117, 48, 208, 213, 241, 196, 6, 250, 106, 216], [13, 98, 81, 146, 52, 170, 229, 92, 219, 69, 20, 191, 6, 233, 231, 70, 103, 196, 158, 193, 212, 219, 171, 43, 15, 204, 80, 61, 233, 54, 241, 46], [16, 205, 255, 214, 216, 66, 138, 39, 25, 111, 117, 173, 202, 34, 70, 107, 110, 47, 22, 243, 147, 54, 172, 66, 194, 56, 223, 107, 245, 46, 166, 208], [40, 175, 52, 122, 139, 239, 153, 241, 252, 144, 185, 34, 138, 167, 103, 122, 18, 39, 19, 203, 10, 247, 197, 191, 56, 41, 185, 104, 35, 88, 168, 150], [10, 177, 27, 153, 98, 28, 132, 101, 217, 66, 100, 62, 113, 71, 155, 77, 1, 21, 68, 191, 63, 30, 17, 114, 214, 70, 157, 167, 28, 78, 203, 38], [27, 169, 165, 48, 240, 141, 252, 245, 22, 15, 62, 122, 220, 162, 121, 29, 4, 107, 49, 215, 184, 44, 13, 75, 229, 252, 87, 46, 165, 208, 22, 234], [20, 209, 29, 76, 79, 215, 226, 242, 124, 206, 171, 95, 34, 165, 203, 131, 124, 13, 165, 54, 104, 252, 240, 220, 209, 189, 30, 255, 194, 50, 173, 12], [1, 142, 233, 199, 20, 165, 57, 41, 103, 117, 252, 231, 14, 206, 53, 185, 255, 1, 233, 237, 55, 6, 228, 97, 201, 139, 138, 216, 171, 107, 124, 222], [42, 141, 184, 47, 6, 182, 52, 172, 127, 226, 104, 244, 136, 184, 74, 7, 245, 107, 248, 31, 144, 50, 103, 212, 190, 79, 69, 142, 248, 201, 74, 23], [38, 62, 89, 230, 211, 180, 130, 176, 163, 52, 218, 9, 97, 19, 152, 209, 64, 192, 12, 226, 182, 35, 177, 63, 83, 103, 45, 80, 89, 152, 183, 26], [45, 215, 106, 171, 110, 160, 72, 83, 13, 164, 181, 43, 129, 207, 25, 75, 129, 199, 48, 89, 214, 84, 132, 40, 139, 14, 168, 151, 70, 96, 145, 191], [16, 190, 57, 207, 62, 230, 82, 127, 218, 67, 138, 88, 86, 19, 30, 181, 21, 245, 157, 74, 216, 144, 182, 221, 124, 6, 184, 141, 12, 35, 77, 253], [39, 174, 243, 39, 63, 227, 142, 120, 107, 243, 250, 247, 92, 177, 45, 251, 202, 23, 106, 89, 118, 198, 164, 251, 199, 195, 109, 12, 224, 46, 239, 189], [39, 35, 217, 30, 146, 168, 242, 222, 125, 49, 14, 174, 150, 200, 58, 125, 182, 163, 48, 123, 72, 21, 248, 85, 143, 158, 218, 24, 226, 212, 76, 35], [24, 242, 187, 168, 119, 87, 83, 179, 84, 131, 9, 227, 36, 52, 236, 200, 168, 146, 46, 251, 150, 236, 121, 21, 124, 102, 110, 82, 101, 71, 37, 49], [33, 135, 139, 236, 244, 33, 187, 44, 190, 88, 111, 45, 44, 198, 179, 172, 122, 135, 29, 255, 220, 97, 52, 95, 230, 57, 173, 177, 130, 33, 223, 148], [27, 120, 64, 175, 215, 146, 229, 89, 144, 133, 56, 108, 207, 135, 127, 136, 40, 134, 54, 80, 247, 103, 202, 105, 34, 181, 180, 171, 238, 171, 120, 40], [32, 15, 194, 191, 203, 112, 179, 171, 121, 221, 45, 149, 125, 184, 206, 208, 177, 146, 205, 200, 189, 241, 126, 222, 210, 188, 29, 245, 73, 183, 147, 178], [5, 171, 235, 102, 81, 84, 53, 161, 140, 112, 21, 174, 183, 29, 49, 172, 93, 249, 28, 63, 5, 179, 78, 110, 246, 151, 81, 212, 129, 95, 242, 5], [6, 149, 253, 219, 81, 158, 150, 101, 83, 134, 69, 193, 156, 92, 157, 255, 13, 77, 209, 94, 241, 191, 132, 206, 82, 14, 208, 194, 207, 186, 215, 27], [29, 200, 48, 218, 37, 233, 64, 42, 253, 218, 171, 51, 205, 135, 98, 13, 88, 44, 75, 109, 146, 132, 238, 239, 170, 111, 177, 112, 164, 139, 242, 62], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 223, 162, 3, 79, 200, 243, 152, 227, 38, 255, 71, 118, 40, 194, 119, 234], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44, 130, 170, 169, 88, 78, 191, 82, 154, 25, 35, 209, 86, 47, 46], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 197, 234, 91, 235, 249, 48, 225, 150, 151, 67, 224, 154, 66, 31, 231, 147, 153], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 236, 133, 72, 93, 178, 18, 130, 9, 152, 103, 17, 186, 179, 149], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 141, 40, 69, 167, 209, 92, 37, 211, 61, 126, 95, 134, 168, 204, 189, 2], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 56, 153, 8, 81, 10, 101, 47, 161, 204, 163, 104, 57, 111, 190], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 150, 107, 208, 18, 136, 237, 51, 116, 154, 144, 251, 70, 30, 23, 120, 139, 116], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 12, 4, 94, 176, 114, 104, 129, 69, 237, 3, 66, 153, 50, 40], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 239, 24, 124, 192, 110, 199, 178, 29, 195, 167, 162, 111, 21, 185, 190, 113], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 171, 54, 104, 69, 120, 135, 75, 247, 193, 248, 215, 4, 13, 148], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 185, 51, 130, 62, 141, 169, 145, 24, 75, 148, 80, 3, 41, 5, 150, 222, 7], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 185, 139, 233, 173, 64, 228, 132, 97, 36, 185, 159, 119, 34, 147], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 4, 130, 133, 192, 188, 188, 214, 81, 172, 62, 72, 253, 203, 144, 115, 197], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 234, 8, 71, 213, 227, 107, 136, 88, 189, 46, 147, 155, 222], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 234, 117, 102, 42, 4, 89, 207, 132, 71, 186, 36, 33, 76, 158, 231, 13, 6], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 46, 196, 243, 107, 105, 8, 180, 35, 150, 75, 243, 5, 158, 215], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 126, 124, 48, 85, 166, 187, 27, 124, 44, 167, 184, 201, 144, 199, 60, 210], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 63, 35, 116, 116, 23, 245, 248, 158, 199, 93, 239, 250, 170, 191], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 76, 244, 152, 48, 199, 179, 153, 207, 200, 231, 52, 152, 137, 247, 168, 45], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 132, 85, 238, 11, 54, 247, 232, 216, 28, 152, 131, 128, 130, 48], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 161, 62, 106, 241, 147, 65, 228, 255, 105, 254, 112, 58, 143, 158, 10, 162, 112], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 237, 50, 209, 133, 10, 181, 16, 232, 127, 214, 154, 117, 59, 65], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 240, 13, 32, 208, 227, 55, 151, 244, 213, 8, 72, 92, 14, 6, 248, 103], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 203, 210, 105, 78, 209, 245, 224, 204, 156, 164, 117, 117, 147, 112], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 247, 191, 37, 136, 102, 251, 11, 108, 35, 35, 195, 18, 138, 125, 151, 80], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 70, 166, 207, 86, 1, 55, 22, 89, 167, 27, 251, 142, 251, 233], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 73, 179, 97, 21, 94, 215, 12, 71, 142, 199, 102, 1, 87, 125, 133, 235, 249], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 66, 222, 106, 135, 30, 12, 102, 72, 122, 69, 200, 131, 13, 243], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 173, 222, 232, 47, 144, 205, 21, 104, 200, 57, 32, 69, 203, 18, 61, 3], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 177, 15, 94, 142, 229, 132, 209, 242, 35, 28, 246, 92, 130, 120], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 113, 165, 234, 216, 50, 235, 28, 35, 198, 56, 18, 218, 245, 144, 23, 57, 57], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 106, 202, 251, 22, 1, 111, 71, 26, 13, 141, 110, 116, 159, 175], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 77, 95, 11, 213, 128, 92, 19, 179, 58, 197, 242, 174, 57, 64, 187, 163], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 136, 7, 44, 49, 28, 125, 61, 129, 196, 248, 94, 192, 2, 124], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 11, 70, 162, 215, 219, 63, 243, 127, 61, 198, 67, 27, 118, 76, 24, 200], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 185, 8, 222, 196, 87, 168, 141, 14, 43, 61, 197, 80, 191, 151], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 59, 122, 93, 170, 83, 122, 78, 165, 105, 37, 9, 118, 17, 239, 100, 103], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 204, 116, 162, 161, 103, 246, 253, 112, 167, 50, 44, 2, 40, 9], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 121, 4, 0, 22, 223, 73, 108, 156, 255, 238, 146, 246, 214, 247, 45, 250], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 193, 197, 139, 83, 204, 223, 45, 235, 136, 169, 72, 124, 65, 204], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 152, 217, 50, 196, 136, 76, 142, 72, 27, 66, 243, 5, 131, 237, 132, 190], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 156, 8, 23, 85, 42, 188, 64, 253, 123, 227, 178, 154, 206, 85], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 234, 84, 157, 12, 73, 243, 164, 242, 148, 11, 240, 94, 77, 39, 203, 71, 28], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 38, 53, 226, 195, 204, 133, 228, 81, 63, 110, 104, 173, 37, 90, 37], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 97, 131, 137, 201, 45, 221, 42, 212, 137, 123, 247, 115, 129, 194, 106, 175], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 82, 80, 42, 75, 247, 246, 109, 7, 107, 248, 147, 77, 136, 194], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 251, 26, 223, 201, 244, 227, 95, 193, 159, 220, 33, 2, 222, 37, 230, 130], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 65, 142, 87, 229, 183, 33, 231, 51, 1, 23, 4, 79, 21, 231], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 234, 182, 161, 66, 40, 176, 242, 31, 145, 189, 195, 244, 156, 246, 194, 100, 204], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 28, 144, 68, 128, 133, 106, 15, 153, 114, 146, 19, 30, 145, 190], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 126, 50, 7, 50, 206, 75, 234, 30, 140, 130, 221, 236, 230, 158, 27, 216], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 175, 63, 245, 165, 133, 181, 246, 110, 93, 254, 75, 141, 240, 1], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 107, 149, 182, 215, 74, 166, 214, 71, 41, 21, 158, 131, 48, 40, 86, 164], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 80, 232, 223, 67, 10, 49, 30, 67, 228, 164, 171, 222, 108, 87], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 213, 21, 244, 155, 30, 134, 100, 149, 61, 57, 140, 236, 127, 213, 184, 9], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 103, 179, 180, 185, 216, 16, 215, 246, 5, 112, 209, 42, 149, 160], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 179, 130, 32, 10, 91, 134, 81, 107, 209, 15, 133, 10, 208, 232, 249, 28, 53], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 217, 112, 4, 254, 250, 238, 152, 212, 162, 218, 26, 26, 82, 203], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 167, 120, 243, 8, 186, 91, 71, 253, 223, 77, 63, 164, 66, 220, 44, 229], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 86, 70, 44, 38, 67, 109, 233, 223, 233, 139, 51, 228, 112, 115], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 141, 174, 50, 24, 207, 143, 71, 239, 135, 239, 102, 103, 150, 117, 45, 131, 88], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 125, 212, 253, 140, 86, 239, 26, 89, 200, 228, 236, 156, 49, 71], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 14, 142, 255, 250, 243, 229, 222, 181, 220, 193, 52, 26, 147, 97, 66, 97], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 141, 84, 3, 209, 151, 181, 124, 110, 177, 112, 82, 231, 113, 255], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 150, 174, 228, 185, 106, 181, 209, 49, 64, 31, 77, 197, 249, 234, 26, 91], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 242, 115, 75, 17, 158, 240, 67, 39, 0, 85, 144, 52, 90, 137], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 8, 14, 87, 228, 36, 247, 229, 142, 94, 48, 6, 255, 64, 240, 99, 46], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 202, 35, 42, 162, 170, 81, 169, 133, 51, 252, 125, 9, 196, 46], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 67, 154, 83, 189, 249, 140, 14, 18, 23, 224, 135, 24, 195, 34, 14, 49, 129], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 62, 238, 14, 72, 7, 150, 96, 57, 2, 42, 35, 105, 113, 100], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 74, 135, 142, 250, 4, 229, 136, 196, 166, 106, 80, 165, 254, 67, 168, 154], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 124, 255, 204, 9, 64, 3, 201, 206, 66, 30, 232, 252, 54, 66], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 60, 215, 172, 133, 179, 57, 211, 226, 72, 0, 189, 35, 38, 35, 63, 192], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 144, 188, 242, 197, 163, 179, 110, 104, 42, 59, 159, 86, 144, 8], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 64, 127, 33, 197, 13, 37, 109, 211, 169, 108, 195, 149, 200, 10, 179, 220], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 14, 123, 104, 35, 217, 27, 151, 126, 204, 18, 236, 226, 209, 249], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 161, 117, 164, 203, 234, 88, 142, 157, 55, 2, 6, 232, 124, 104, 29, 31, 22], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 4, 131, 226, 189, 166, 21, 124, 77, 179, 88, 43, 87, 135, 170], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 151, 132, 204, 143, 111, 188, 87, 180, 77, 236, 3, 250, 224, 153, 250, 220], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 223, 113, 1, 188, 8, 188, 125, 220, 183, 139, 244, 146, 252, 229], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 177, 107, 217, 165, 70, 95, 2, 239, 148, 119, 49, 103, 86, 206, 50, 253], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 127, 150, 16, 232, 101, 185, 164, 162, 135, 189, 248, 160, 176, 152], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 254, 162, 178, 230, 239, 169, 187, 242, 53, 152, 12, 108, 38, 240, 214, 15], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 9, 210, 187, 91, 134, 214, 1, 148, 57, 218, 220, 76, 7, 230], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 227, 47, 194, 109, 91, 4, 168, 43, 31, 217, 198, 124, 73, 131, 19, 183, 209], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 211, 75, 126, 169, 10, 110, 121, 57, 138, 131, 219, 99, 187, 117], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 181, 95, 73, 33, 98, 172, 217, 173, 178, 206, 118, 97, 202, 48, 108, 213], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 114, 75, 36, 32, 225, 54, 7, 248, 191, 191, 129, 242, 82, 124], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 132, 128, 56, 98, 37, 155, 153, 198, 77, 171, 199, 227, 109, 174, 15, 75, 100], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 146, 6, 17, 21, 135, 184, 33, 41, 156, 236, 19, 18, 76, 48], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 124, 183, 192, 71, 103, 164, 62, 124, 148, 40, 245, 181, 242, 45, 8, 162, 71], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 113, 166, 149, 61, 128, 8, 209, 86, 26, 181, 22, 28, 34, 218], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 179, 67, 196, 55, 228, 16, 16, 25, 26, 40, 192, 211, 243, 62, 140, 193, 107], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 131, 208, 230, 139, 58, 228, 47, 40, 50, 175, 251, 208, 129, 248], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 251, 137, 18, 118, 130, 48, 27, 97, 252, 250, 253, 12, 79, 84, 97, 202], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 188, 133, 24, 180, 34, 163, 85, 21, 9, 24, 82, 50, 2, 188], [43, 203, 198, 218, 92, 131, 178, 51, 8, 66, 62, 0, 148, 13, 113, 224, 28, 234, 163, 83, 92, 101, 3, 32, 210, 71, 202, 63, 29, 112, 33, 97], [8, 87, 168, 202, 161, 235, 181, 200, 55, 72, 93, 200, 137, 176, 61, 184, 14, 70, 251, 228, 3, 38, 148, 221, 128, 226, 192, 229, 164, 173, 191, 111], [25, 170, 141, 105, 178, 168, 241, 34, 251, 77, 187, 73, 186, 226, 77, 240, 52, 57, 166, 194, 7, 95, 181, 136, 124, 197, 103, 75, 11, 246, 118, 56], [36, 61, 7, 184, 223, 33, 56, 151, 109, 175, 20, 95, 157, 6, 243, 67, 28, 106, 45, 139, 32, 230, 172, 123, 236, 56, 232, 173, 208, 68, 15, 115], [4, 193, 140, 178, 247, 240, 220, 239, 100, 85, 112, 93, 143, 148, 107, 237, 187, 225, 67, 227, 239, 15, 61, 172, 226, 207, 223, 189, 88, 137, 68, 212], [15, 174, 222, 56, 137, 148, 100, 127, 162, 45, 112, 232, 45, 40, 179, 58, 126, 157, 144, 122, 117, 190, 179, 118, 0, 246, 214, 76, 64, 125, 151, 30], [2, 145, 163, 204, 25, 11, 90, 207, 226, 187, 56, 226, 236, 92, 202, 145, 248, 251, 27, 64, 199, 7, 182, 79, 166, 205, 92, 62, 149, 203, 25, 87], [2, 167, 156, 229, 39, 234, 35, 4, 199, 4, 227, 79, 31, 203, 231, 122, 60, 226, 242, 162, 189, 167, 35, 175, 25, 41, 117, 97, 39, 106, 51, 165], [18, 28, 118, 245, 86, 5, 72, 127, 114, 40, 186, 249, 184, 205, 201, 228, 120, 166, 89, 226, 99, 72, 20, 168, 162, 131, 197, 173, 145, 149, 169, 110], [33, 206, 56, 97, 196, 248, 147, 90, 180, 51, 140, 237, 243, 55, 67, 18, 119, 190, 55, 110, 60, 202, 174, 124, 12, 93, 240, 86, 6, 154, 48, 124], [0, 245, 168, 147, 81, 28, 189, 123, 81, 252, 224, 55, 101, 241, 137, 165, 128, 145, 223, 205, 30, 175, 90, 53, 154, 184, 60, 22, 129, 200, 33, 32], [7, 159, 64, 55, 80, 27, 37, 7, 176, 0, 94, 20, 71, 177, 247, 130, 173, 28, 0, 86, 200, 171, 31, 24, 129, 128, 195, 143, 96, 87, 99, 244], [21, 171, 171, 100, 12, 234, 137, 48, 54, 66, 241, 229, 36, 22, 147, 66, 129, 177, 148, 130, 153, 203, 159, 229, 190, 228, 92, 209, 190, 106, 121, 14], [30, 54, 164, 219, 233, 150, 6, 239, 103, 236, 58, 80, 148, 240, 251, 253, 57, 128, 236, 107, 34, 118, 71, 70, 174, 195, 30, 215, 155, 247, 205, 103], [12, 20, 218, 105, 77, 14, 182, 241, 47, 29, 166, 229, 2, 35, 28, 1, 239, 158, 177, 59, 144, 56, 33, 64, 203, 27, 248, 182, 149, 66, 233, 159], [15, 16, 64, 19, 8, 38, 71, 18, 47, 87, 150, 41, 187, 127, 176, 92, 186, 10, 150, 91, 1, 199, 3, 188, 165, 213, 145, 90, 64, 167, 56, 105], [33, 202, 194, 39, 16, 224, 221, 91, 161, 202, 0, 21, 127, 76, 72, 94, 70, 226, 214, 36, 214, 244, 249, 26, 135, 36, 156, 200, 66, 10, 143, 115], [30, 231, 133, 207, 2, 39, 190, 118, 140, 178, 153, 247, 120, 210, 22, 231, 96, 33, 97, 33, 27, 149, 136, 5, 139, 230, 28, 83, 254, 236, 39, 20], [9, 153, 20, 228, 26, 65, 174, 248, 235, 174, 23, 73, 237, 83, 240, 248, 203, 8, 4, 164, 3, 246, 221, 58, 22, 143, 10, 147, 107, 218, 228, 184], [29, 101, 108, 40, 223, 151, 49, 248, 250, 172, 153, 254, 110, 75, 118, 191, 96, 176, 247, 255, 14, 8, 92, 95, 79, 233, 2, 161, 8, 206, 210, 89], [29, 63, 206, 43, 110, 71, 133, 209, 128, 61, 92, 181, 144, 149, 236, 104, 105, 88, 106, 133, 71, 22, 124, 170, 113, 222, 31, 84, 129, 124, 200, 246], [43, 226, 13, 89, 23, 195, 33, 56, 204, 64, 64, 162, 205, 149, 245, 62, 108, 172, 172, 187, 212, 97, 43, 150, 161, 84, 199, 27, 5, 244, 63, 4], [43, 148, 165, 5, 251, 229, 206, 177, 133, 191, 172, 224, 45, 168, 205, 232, 225, 119, 172, 57, 112, 235, 194, 142, 140, 83, 227, 62, 174, 44, 80, 128], [34, 252, 241, 41, 71, 214, 185, 206, 248, 28, 64, 37, 160, 182, 175, 35, 205, 51, 137, 214, 156, 79, 203, 133, 168, 203, 117, 171, 156, 7, 231, 163], [17, 95, 89, 84, 227, 244, 252, 170, 108, 27, 231, 75, 243, 41, 80, 88, 49, 21, 234, 116, 28, 251, 168, 242, 219, 141, 127, 31, 126, 123, 240, 141], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 182, 82, 149, 37, 59, 110, 203, 226, 81, 237, 140, 230, 91, 138, 26, 178], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 71, 209, 151, 25, 159, 163, 55, 1, 116, 248, 3, 237, 233, 110], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 5, 255, 44, 129, 115, 177, 87, 229, 43, 214, 192, 124, 219, 161, 238, 191], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 185, 174, 90, 165, 99, 210, 180, 157, 97, 69, 59, 238, 215, 164], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 64, 135, 135, 90, 246, 255, 172, 22, 78, 113, 118, 48, 158, 251, 72, 212], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 63, 162, 1, 70, 88, 202, 255, 115, 228, 170, 80, 101, 145, 235], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 8, 185, 226, 154, 183, 37, 22, 75, 104, 164, 183, 242, 74, 121, 243, 58], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 67, 254, 7, 115, 29, 108, 186, 194, 245, 141, 28, 68, 74, 171]];
        #[rustfmt::skip]
        let public_inputs = vec![3, 204, 82, 161, 76, 221, 172, 239, 166, 62, 108, 35, 132, 105, 162, 46, 151, 109, 35, 202, 194, 65, 226, 192, 190, 122, 211, 34, 241, 255, 255, 204];
        #[rustfmt::skip]
        let verification_key: [[u8; 32]; 115] = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 56, 87, 89, 113, 131, 13, 146, 31, 186, 97, 168, 3, 121, 207, 221, 69], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 123, 173, 47, 112, 22, 163, 29, 239, 248, 126, 160, 100, 176, 211], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 206, 92, 111, 25, 167, 147, 161, 147, 174, 127, 248, 19, 108, 161, 108, 67, 4], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 142, 92, 3, 254, 254, 57, 197, 197, 189, 207, 100, 7, 215, 10], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 186, 82, 224, 228, 78, 95, 176, 211, 138, 97, 135, 40, 108, 18, 26, 144, 237], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 3, 19, 205, 145, 100, 240, 228, 88, 108, 127, 43, 217, 31, 36], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 184, 27, 5, 120, 149, 129, 71, 51, 74, 123, 37, 216, 88, 54, 208, 164], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 50, 190, 120, 177, 105, 137, 139, 91, 129, 88, 51, 187, 159, 29], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 246, 180, 85, 255, 12, 235, 63, 92, 69, 228, 113, 204, 44, 221, 66, 138], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 147, 50, 154, 92, 163, 249, 92, 164, 62, 28, 209, 85, 117, 173], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 89, 186, 62, 57, 122, 157, 9, 60, 157, 106, 153, 174, 179, 57, 62, 12], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 195, 100, 176, 61, 247, 249, 203, 24, 227, 44, 87, 139, 21, 82], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 244, 26, 214, 231, 138, 150, 172, 185, 236, 16, 130, 55, 250, 161, 191, 166, 253], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 91, 182, 173, 94, 132, 66, 236, 187, 82, 20, 216, 108, 219, 185], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 242, 5, 199, 71, 145, 80, 91, 141, 210, 248, 180, 226, 127, 236, 16, 239], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 212, 66, 129, 116, 134, 79, 197, 252, 145, 204, 68, 4, 248, 17], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106, 211, 249, 145, 142, 61, 184, 220, 19, 167, 97, 231, 38, 141, 19, 158, 104], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 159, 48, 70, 43, 22, 42, 199, 152, 207, 197, 201, 217, 190, 57], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 111, 27, 175, 205, 140, 11, 14, 99, 2, 73, 109, 135, 1, 30, 119, 224, 43], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 241, 246, 10, 208, 234, 6, 105, 101, 19, 254, 93, 161, 142, 44], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 164, 60, 66, 72, 38, 124, 105, 233, 185, 25, 157, 199, 140, 91, 11, 67, 95], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 40, 89, 113, 174, 8, 79, 137, 184, 217, 67, 180, 55, 127, 123], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 234, 91, 62, 252, 110, 166, 178, 58, 163, 56, 21, 84, 203, 173, 166, 232], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44, 32, 245, 133, 183, 103, 170, 140, 187, 183, 90, 105, 150, 5, 17], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 217, 157, 95, 152, 158, 53, 82, 129, 62, 189, 211, 44, 238, 96, 238, 253, 130], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 193, 102, 166, 251, 229, 55, 240, 20, 38, 125, 226, 103, 135, 86], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159, 253, 215, 250, 64, 125, 206, 85, 8, 27, 25, 131, 33, 147, 206, 195, 117], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44, 122, 96, 159, 144, 47, 129, 84, 114, 237, 85, 220, 230, 19, 205], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 52, 102, 146, 57, 107, 206, 57, 180, 91, 15, 118, 193, 219, 88, 119, 14], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 156, 80, 129, 194, 246, 11, 51, 175, 117, 103, 32, 136, 31, 2], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 233, 77, 65, 137, 142, 115, 226, 30, 57, 163, 15, 101, 12, 48, 148, 56], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 107, 15, 75, 139, 68, 126, 243, 64, 121, 123, 25, 125, 104, 183], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 151, 181, 9, 20, 114, 64, 229, 134, 206, 220, 47, 164, 153, 160, 112, 8], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 94, 239, 120, 62, 201, 50, 124, 220, 31, 252, 246, 138, 81, 97], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 242, 250, 102, 53, 116, 20, 214, 127, 194, 132, 130, 243, 240, 114, 201, 3, 2], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 73, 129, 180, 197, 165, 192, 97, 149, 152, 47, 59, 82, 68, 247], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 91, 153, 174, 55, 40, 133, 172, 186, 31, 71, 51, 43, 97, 17, 92, 54, 181], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 134, 96, 208, 116, 243, 90, 71, 120, 0, 4, 79, 108, 175, 48], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 228, 146, 35, 227, 106, 158, 102, 200, 9, 60, 231, 199, 224, 228, 218, 41], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 222, 23, 30, 109, 83, 80, 158, 74, 180, 51, 116, 240, 126, 66], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 9, 215, 210, 187, 151, 161, 110, 131, 48, 240, 125, 179, 147, 18, 54, 155], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 25, 224, 144, 141, 220, 93, 239, 179, 193, 129, 205, 224, 203, 76], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 154, 219, 87, 187, 156, 68, 252, 82, 81, 4, 228, 75, 72, 192, 250, 205, 158], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 53, 178, 150, 202, 64, 209, 33, 245, 154, 20, 30, 110, 8, 139], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 179, 154, 96, 238, 127, 208, 64, 114, 9, 147, 37, 213, 39, 111, 94, 200], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 66, 254, 36, 57, 174, 223, 178, 35, 187, 246, 171, 171, 250, 99], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 235, 43, 204, 248, 38, 158, 236, 17, 34, 172, 222, 99, 5, 246, 252, 252, 76], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 111, 178, 121, 95, 236, 122, 166, 138, 120, 168, 144, 122, 244, 244], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 109, 46, 176, 36, 59, 74, 223, 231, 40, 254, 21, 129, 183, 151, 126, 250], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 5, 55, 104, 52, 101, 81, 145, 128, 249, 1, 72, 72, 168, 19], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 189, 248, 230, 96, 129, 90, 39, 133, 68, 70, 51, 37, 166, 59, 18, 141, 210], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 59, 193, 53, 103, 174, 98, 15, 17, 68, 72, 158, 182, 119, 107], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 28, 115, 56, 33, 41, 183, 15, 122, 228, 55, 85, 13, 247, 37, 15, 56], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 108, 144, 70, 71, 108, 19, 245, 246, 108, 223, 130, 46, 1, 87], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 225, 251, 88, 75, 102, 92, 35, 23, 236, 134, 119, 80, 85, 177, 106, 41, 139], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 59, 229, 79, 59, 168, 107, 23, 63, 80, 5, 129, 236, 176, 157], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 118, 103, 46, 106, 188, 230, 5, 27, 191, 99, 171, 123, 150, 249, 89, 47, 101], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 142, 0, 86, 107, 242, 56, 165, 65, 79, 200, 176, 174, 229, 86], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 156, 108, 190, 200, 134, 19, 192, 0, 199, 22, 40, 241, 81, 133, 230, 201, 249], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 207, 10, 237, 109, 66, 246, 184, 210, 160, 141, 154, 188, 171, 108], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 250, 118, 76, 113, 235, 5, 148, 151, 250, 207, 82, 91, 70, 196, 209, 246, 234], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 74, 27, 66, 252, 177, 165, 20, 234, 87, 208, 145, 102, 229, 200], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 80, 45, 203, 111, 83, 33, 93, 59, 66, 146, 209, 40, 53, 133, 83, 203], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 141, 246, 80, 251, 136, 107, 219, 204, 33, 180, 97, 7, 211, 83], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 111, 33, 201, 78, 52, 152, 26, 109, 200, 81, 11, 225, 47, 235, 240, 178], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 222, 60, 254, 222, 118, 173, 55, 102, 4, 20, 142, 153, 12, 42], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 122, 212, 49, 128, 140, 70, 224, 144, 47, 219, 195, 74, 53, 83, 198, 191], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 215, 214, 103, 28, 23, 70, 188, 124, 230, 59, 3, 119, 202, 188], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 79, 72, 129, 118, 191, 247, 183, 39, 98, 78, 86, 123, 250, 8, 68, 252], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 216, 168, 230, 22, 107, 218, 159, 173, 118, 107, 212, 162, 8, 243], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 227, 111, 138, 233, 213, 28, 201, 196, 216, 233, 25, 227, 61, 120, 15, 24, 28], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 81, 10, 159, 139, 168, 163, 49, 204, 116, 216, 209, 210, 144, 215], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 37, 213, 186, 41, 38, 124, 117, 117, 251, 197, 21, 187, 219, 114, 40, 102], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 165, 207, 213, 209, 105, 28, 134, 120, 88, 255, 200, 66, 101, 160], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 238, 172, 48, 168, 82, 85, 136, 228, 77, 195, 97, 226, 249, 128, 62, 66, 237], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 31, 133, 227, 243, 173, 232, 237, 120, 145, 228, 241, 98, 9, 174], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 13, 76, 133, 221, 247, 240, 130, 239, 74, 224, 213, 211, 184, 98, 60, 250], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 14, 7, 197, 93, 88, 135, 54, 72, 173, 68, 239, 97, 170, 176], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 237, 50, 50, 229, 244, 28, 73, 246, 72, 136, 12, 104, 163, 49, 181, 185, 129], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 245, 31, 232, 79, 171, 38, 253, 240, 155, 26, 171, 163, 235, 102], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 24, 97, 97, 106, 73, 8, 35, 87, 96, 252, 183, 102, 161, 161, 190, 133], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 186, 175, 61, 208, 177, 44, 124, 210, 92, 188, 225, 247, 156, 111], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 216, 20, 125, 13, 15, 5, 235, 177, 167, 244, 251, 217, 194, 91, 142, 218], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 69, 189, 140, 165, 238, 233, 168, 136, 114, 135, 219, 178, 21, 124], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 57, 125, 104, 67, 128, 187, 143, 21, 220, 30, 119, 99, 217, 35, 69, 248], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 188, 171, 160, 69, 241, 27, 134, 150, 228, 111, 209, 138, 154, 86], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 73, 60, 234, 147, 171, 86, 33, 180, 115, 177, 137, 147, 139, 111, 153, 37], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 198, 176, 247, 72, 112, 61, 228, 224, 222, 195, 172, 43, 165, 207], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 146, 102, 152, 222, 131, 101, 78, 196, 35, 169, 137, 34, 216, 2, 157, 137], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 159, 134, 19, 220, 176, 80, 173, 89, 52, 39, 207, 163, 177, 122], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 116, 177, 75, 167, 5, 130, 131, 137, 186, 144, 235, 173, 125, 51, 119, 254], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 188, 106, 242, 184, 178, 150, 132, 167, 102, 205, 217, 158, 97, 96], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 102, 154, 240, 42, 27, 48, 59, 2, 75, 194, 1, 184, 216, 241, 60, 146], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 223, 213, 101, 154, 84, 128, 86, 92, 161, 71, 39, 62, 90, 145], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 210, 140, 30, 187, 46, 48, 227, 134, 207, 99, 151, 204, 216, 172, 213, 220], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 106, 20, 145, 91, 182, 233, 92, 80, 73, 154, 2, 17, 151, 78], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 121, 47, 151, 93, 50, 117, 233, 9, 222, 85, 223, 200, 239, 25, 6, 111], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 124, 102, 47, 234, 4, 35, 107, 4, 216, 252, 146, 227, 102, 163], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 130, 208, 46, 115, 61, 104, 188, 141, 80, 121, 113, 78, 29, 250, 178, 157], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 20, 3, 127, 52, 0, 2, 60, 47, 1, 127, 16, 52, 183, 61], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 238, 129, 178, 58, 136, 127, 41, 144, 73, 177, 76, 17, 233, 132, 96, 214], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 86, 206, 65, 246, 176, 190, 19, 185, 194, 103, 71, 98, 27, 130], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 213, 130, 125, 99, 56, 199, 134, 86, 192, 209, 44, 161, 174, 166, 239, 44, 124], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 169, 143, 45, 227, 221, 218, 84, 125, 143, 109, 228, 231, 37, 222], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 244, 217, 217, 109, 224, 127, 229, 8, 240, 140, 224, 123, 92, 112, 128, 185], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 186, 32, 51, 199, 218, 81, 90, 144, 59, 211, 16, 60, 213, 56], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59, 2, 96, 254, 34, 141, 170, 220, 7, 98, 223, 19, 82, 15, 189, 172, 253], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 12, 252, 83, 67, 236, 171, 176, 211, 99, 179, 67, 120, 196, 68]];
        VerifierInputs {
            key_hash,
            proof: proof.into_iter().map(|x| x.to_vec()).collect(),
            public_inputs,
            verification_key: verification_key.into_iter().map(|x| x.to_vec()).collect(),
        }
    }

    #[test]
    fn test_balanced_barretenberg_aggregator() {
        // Initialize the structured reference string
        init_srs();
        let batch: [VerifierInputs; 8] = std::array::repeat(noir_recursive_no_zk_proof());
        type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT =
            RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
        // Make a simple aggregator that directly computes the root
        let mut barretenberg_aggregator = BarretenbergAggregatorT::new(0usize..);
        // Push the random batch onto the aggregator
        barretenberg_aggregator.push_internal_proofs(batch.to_vec());
        // Make the aggregator process the proofs in the queue
        barretenberg_aggregator.step();
        // Extract the generated root proof
        let mut barretenberg_aggregator_proof = barretenberg_aggregator
            .pop_recursive_proof()
            .expect("Barretenberg aggregator should generate at least one proof")
            .1;
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push 4 sub-aggregators to actually handle the computations
        recursive_aggregator
            .insert_sub_aggregator(Box::new(BarretenbergAggregatorT::new(0usize..)));
        recursive_aggregator
            .insert_sub_aggregator(Box::new(BarretenbergAggregatorT::new(0usize..)));
        recursive_aggregator
            .insert_sub_aggregator(Box::new(BarretenbergAggregatorT::new(0usize..)));
        recursive_aggregator
            .insert_sub_aggregator(Box::new(BarretenbergAggregatorT::new(0usize..)));
        // Push some work onto the recursive aggregator
        recursive_aggregator.push_internal_proofs(batch.to_vec());
        // Repeatedly step through distribution and consolidation
        let mut recursive_aggregator_proof = loop {
            if let Some(proof) = recursive_aggregator.pop_recursive_proof() {
                break proof;
            }
            recursive_aggregator.step();
            thread::sleep(Duration::from_secs(1));
        };
        // Finally, ensure that the Merkle roots agree
        barretenberg_aggregator_proof.proof = vec![];
        recursive_aggregator_proof.1.proof = vec![];
        assert_eq!(barretenberg_aggregator_proof, recursive_aggregator_proof.1);
        assert_eq!(barretenberg_aggregator.pop_recursive_proof(), None);
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }

    #[test]
    pub fn bench_balanced_threaded_barretenberg_aggregator() {
        const BATCH_SIZE: usize = 8;
        const NUM_AGGREGATORS: usize = 8;
        const BATCH_COUNT: usize = 4;
        // Initialize the structured reference string
        init_srs();
        let batch: [VerifierInputs; BATCH_SIZE] = std::array::repeat(noir_recursive_no_zk_proof());
        type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT =
            RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push NUM_AGGREGATORS sub-aggregators to actually handle the computations
        for _i in 0..NUM_AGGREGATORS {
            recursive_aggregator.insert_sub_aggregator(Box::new(ThreadedAggregator::new(
                0..,
                0..,
                || BarretenbergAggregatorT::new(0usize..),
            )));
        }
        // Push some work onto the recursive aggregator
        for _i in 0..BATCH_COUNT {
            recursive_aggregator.push_internal_proofs(batch.to_vec());
        }
        // Repeatedly step through distribution and consolidation
        for _i in 0..BATCH_COUNT {
            while let None = recursive_aggregator.pop_recursive_proof() {
                recursive_aggregator.step();
                thread::sleep(Duration::from_secs(1));
            }
        }
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }

    #[test]
    pub fn bench_mixed_threaded_barretenberg_aggregator() {
        const BATCH_SIZE: usize = 8;
        const NUM_AGGREGATORS: usize = 4;
        const BATCH_COUNT: usize = 4;
        const SUB_AGGREGATORS: [&str; 1] = ["127.0.0.1:8001"];
        // Initialize the structured reference string
        init_srs();
        let batch: [VerifierInputs; BATCH_SIZE] = std::array::repeat(noir_recursive_no_zk_proof());
        type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT =
            RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push NUM_AGGREGATORS sub-aggregators to actually handle the computations
        for _i in 0..NUM_AGGREGATORS {
            recursive_aggregator.insert_sub_aggregator(Box::new(ThreadedAggregator::new(
                0..,
                0..,
                || BarretenbergAggregatorT::new(0usize..),
            )));
        }
        // Also push some TCP sub-aggregators onto the aggregator
        for addr in SUB_AGGREGATORS {
            recursive_aggregator.insert_sub_aggregator(Box::new(TcpStreamAggregator::new(
                0usize..,
                0usize..,
                &addr,
            )));
        }
        // Push some work onto the recursive aggregator
        for _i in 0..BATCH_COUNT {
            recursive_aggregator.push_internal_proofs(batch.to_vec());
        }
        // Repeatedly step through distribution and consolidation
        for _i in 0..BATCH_COUNT {
            while let None = recursive_aggregator.pop_recursive_proof() {
                recursive_aggregator.step();
                thread::sleep(Duration::from_secs(1));
            }
        }
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }

    #[test]
    fn test_balanced_threaded_barretenberg_aggregator() {
        // Initialize the structured reference string
        init_srs();
        let batch: [VerifierInputs; 8] = std::array::repeat(noir_recursive_no_zk_proof());
        type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
        type RecursiveAggregatorT =
            RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
        // Make a simple aggregator that directly computes the root
        let mut barretenberg_aggregator = BarretenbergAggregatorT::new(0usize..);
        // Push the random batch onto the aggregator
        barretenberg_aggregator.push_internal_proofs(batch.to_vec());
        // Make the aggregator process the proofs in the queue
        barretenberg_aggregator.step();
        // Extract the generated root proof
        let mut barretenberg_aggregator_proof = barretenberg_aggregator
            .pop_recursive_proof()
            .expect("Barretenberg aggregator should generate at least one proof")
            .1;
        // Make a more complex aggregator
        let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
        // Push 4 sub-aggregators to actually handle the computations
        let agg = ThreadedAggregator::new(0.., 0.., || BarretenbergAggregatorT::new(0usize..));
        recursive_aggregator.insert_sub_aggregator(Box::new(agg));
        let agg = ThreadedAggregator::new(0.., 0.., || BarretenbergAggregatorT::new(0usize..));
        recursive_aggregator.insert_sub_aggregator(Box::new(agg));
        let agg = ThreadedAggregator::new(0.., 0.., || BarretenbergAggregatorT::new(0usize..));
        recursive_aggregator.insert_sub_aggregator(Box::new(agg));
        let agg = ThreadedAggregator::new(0.., 0.., || BarretenbergAggregatorT::new(0usize..));
        recursive_aggregator.insert_sub_aggregator(Box::new(agg));
        // Push some work onto the recursive aggregator
        recursive_aggregator.push_internal_proofs(batch.to_vec());
        // Repeatedly step through distribution and consolidation
        let mut recursive_aggregator_proof = loop {
            if let Some(proof) = recursive_aggregator.pop_recursive_proof() {
                break proof;
            }
            recursive_aggregator.step();
            thread::sleep(Duration::from_secs(1));
        };
        // Finally, ensure that the Merkle roots agree. Exclude proofs from the comparison
        // since they are non-deterministic.
        barretenberg_aggregator_proof.proof = vec![];
        recursive_aggregator_proof.1.proof = vec![];
        assert_eq!(barretenberg_aggregator_proof, recursive_aggregator_proof.1);
        assert_eq!(barretenberg_aggregator.pop_recursive_proof(), None);
        assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_tcp_stream_aggregator(batch: [[u8; 32]; 256]) {
            type MerkleAggregatorT = MerkleAggregator<RangeFrom<usize>, RangeFrom<usize>>;
            type TcpStreamAggregatorT = TcpStreamAggregator<RangeFrom<usize>, RangeFrom<usize>, [u8; 32]>;
            // Create a channel to synchronize the threads and pass the bound address.
            let (tx, rx) = mpsc::channel();
            let handle = thread::spawn(move || {
                // Make a simple aggregator that directly computes the root
                let merkle_aggregator = MerkleAggregatorT::new(0usize..);
                // Build and run a TCP aggregator server using the Merkle aggregator
                let mut tcp_aggregator = TcpAggregatorServer::new(&"0.0.0.0:0", merkle_aggregator);
                // Retrieve the actual address/port the OS assigned.
                let addr = tcp_aggregator.listener.local_addr().expect("Failed to get local address");
                // Signal to the main thread that the listener is ready, sending the port.
                tx.send(addr).expect("Failed to send address to main thread");
                tcp_aggregator.run().expect("aggregator server should shutdown successfully");
            });
            // Wait for the server thread to bind and tell us its address.
            // This entirely prevents the "Connection Refused" race condition.
            let server_addr = rx.recv().expect("Server thread panicked or dropped the sender");
            // Make an aggregator that forwards requests to the given IP address
            let mut tcp_aggregator: TcpStreamAggregatorT = TcpStreamAggregator::new(0usize.., 0usize.., &server_addr);
            // Push the random batch onto the aggregator
            tcp_aggregator.push_internal_proofs(batch.to_vec());
            // Make the aggregator process the proofs in the queue
            while let None = tcp_aggregator.pop_recursive_proof() {
                tcp_aggregator.step();
                thread::sleep(Duration::from_secs(1));
                tcp_aggregator.sync();
            }
            // Finally send message for the server to shutdown
            tcp_aggregator.shutdown();
            // Wait for the server thread to shutdown
            handle.join().expect("unable to join server thread");
            // Finally destroy the TCP aggregator
            std::mem::drop(tcp_aggregator);
        }

        #[test]
        fn test_balanced_merkle_aggregator(batch: [[u8; 32]; 256]) {
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
            let recursive_aggregator_proof = loop {
                if let Some(proof) = recursive_aggregator.pop_recursive_proof() {
                    break proof;
                }
                recursive_aggregator.step();
            };
            // Finally, ensure that the Merkle roots agree
            assert_eq!(merkle_aggregator.pop_recursive_proof(), Some(recursive_aggregator_proof));
            assert_eq!(merkle_aggregator.pop_recursive_proof(), None);
            assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
        }

        #[test]
        fn test_imbalanced_merkle_aggregator(batch: [[u8; 32]; 256]) {
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
            let recursive_aggregator_proof = loop {
                if let Some(proof) = recursive_aggregator.pop_recursive_proof() {
                    break proof;
                }
                recursive_aggregator.step();
            };
            // Finally, ensure that the Merkle roots agree
            assert_eq!(merkle_aggregator.pop_recursive_proof(), Some(recursive_aggregator_proof));
            assert_eq!(merkle_aggregator.pop_recursive_proof(), None);
            assert_eq!(recursive_aggregator.pop_recursive_proof(), None);
        }
    }
}
