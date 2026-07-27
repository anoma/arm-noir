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
use barretenberg_rs::generated_types::CircuitProveResponse;
use proptest::prelude::*;

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
    let mut aggregator: MerkleAggregator<RangeFrom<usize>, RangeFrom<usize>> = MerkleAggregator::new(0usize..);
    aggregator.push_internal_proofs(vec![[0; 32], [1; 32]]);
    aggregator.step();
    println!("Recursive proof: {:?}", aggregator.pop_recursive_proof());
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
