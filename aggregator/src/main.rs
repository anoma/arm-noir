use std::collections::VecDeque;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Range;
use barretenberg_rs::generated_types::CircuitProveResponse;

/// Type alias to ease generic usage of aggregators
type AggregatorBox<A> = Box<dyn Aggregator<AggregatorId = <A as Aggregator>::AggregatorId, Proof = <A as Aggregator>::Proof, BatchId = <A as Aggregator>::BatchId>>;

/// Unambiguous identification of batch ID
type QualifiedBatchId<A> = (<A as Aggregator>::AggregatorId, <A as Aggregator>::BatchId);

/// The interface shared by all proof aggregators
trait Aggregator {
    /// The type that holds aggregator IDs
    type AggregatorId;
    /// The type that holds batch IDs
    type BatchId;
    /// The type that holds proofs
    type Proof;
    /// Push a leaf proof onto a queue of leaf proofs to aggregate
    fn push_leaf_proof(&mut self, proof: Self::Proof);
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

/// Proof aggregator that works purely by delegating to workers
struct RecursiveAggregator<AggregatorId, BatchId, Proof, AggregatorIds: Iterator<Item = AggregatorId> = Range<AggregatorId>, BatchIds: Iterator<Item = BatchId> = Range<BatchId>> {
    /// The ID of this aggregator in its local namespace
    pub aggregator_id: AggregatorId,
    /// Minimum batch size that can be formed from leaf proofs
    pub leaf_batch_size: usize,
    /// Queue of leaf proofs to be aggregated
    pub leaf_proofs: VecDeque<Proof>,
    /// Queue of internal proofs to be aggregated
    pub internal_proofs: VecDeque<(BatchId, Vec<Proof>)>,
    /// Queue of produced recursive proofs
    pub recursive_proofs: VecDeque<(BatchId, Proof)>,
    /// Temporary place to store recursive proofs from sub-aggregators
    pub sub_recursive_proofs: HashMap<(AggregatorId, BatchId), Proof>,
    /// Proof aggregators to offload work onto
    pub sub_aggregators: HashMap<AggregatorId, Box<dyn Aggregator<AggregatorId = AggregatorId, BatchId = BatchId, Proof = Proof>>>,
    /// The ID to assign to the next sub aggregator
    pub free_aggregator_ids: AggregatorIds,
    /// The ID to assign to the next batch
    pub free_batch_ids: BatchIds,
    /// Map proofs to their parents
    pub proof_parents: HashMap<(AggregatorId, BatchId), (AggregatorId, BatchId)>,
    /// Map proofs to their children
    pub proof_children: HashMap<(AggregatorId, BatchId), ((AggregatorId, BatchId), (AggregatorId, BatchId))>,
    /// Map qualified batch IDs to their original batch IDs
    pub proof_aliases: HashMap<(AggregatorId, BatchId), BatchId>,
}

impl<AggregatorId, BatchId, Proof, AggregatorIds: Iterator<Item = AggregatorId>, BatchIds: Iterator<Item = BatchId>> RecursiveAggregator<AggregatorId, BatchId, Proof, AggregatorIds, BatchIds> {
    fn gen_aggregator_id(&mut self) -> AggregatorId {
        self.free_aggregator_ids.next().expect("Exhausted free aggregator IDs")
    }
    
    fn gen_batch_id(&mut self) -> BatchId {
        self.free_batch_ids.next().expect("Exhausted free batch IDs")
    }
}

impl<AggregatorId: Hash + Eq + Copy + Debug, BatchId: Hash + Eq + Copy, Proof, AggregatorIds: Iterator<Item = AggregatorId>, BatchIds: Iterator<Item = BatchId>> Aggregator for RecursiveAggregator<AggregatorId, BatchId, Proof, AggregatorIds, BatchIds> {
    type AggregatorId = AggregatorId;
    type BatchId = BatchId;
    type Proof = Proof;
    
    fn push_leaf_proof(&mut self, proof: Self::Proof) {
        self.leaf_proofs.push_back(proof);
    }

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>) -> Self::BatchId {
        // Batch sizes must be powers of two
        assert!(proofs.len().is_power_of_two());
        // More than one proof must be supplied for there to be work to do
        assert!(proofs.len() > 1);
        let batch_id = self.gen_batch_id();
        self.internal_proofs.push_back((batch_id, proofs));
        batch_id
    }

    fn pop_recursive_proof(&mut self) -> Option<(Self::BatchId, Self::Proof)> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        // Get the proofs queued in this aggregator
        let local = self.leaf_proofs.len() +
            self.internal_proofs.iter().map(|s| s.1.len()).sum::<usize>();
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
        let aggregator_id = self.gen_aggregator_id();
        self.sub_aggregators.insert(aggregator_id, sub_aggregator);
        aggregator_id
    }

    fn remove_sub_aggregator(&mut self, id: &Self::AggregatorId) -> Option<AggregatorBox<Self>> {
        self.sub_aggregators.remove(id)
    }

    fn step(&mut self) {
        // If enough leaf proofs have been queued, then push them into the internaal proof queue
        if self.leaf_proofs.len() >= self.leaf_batch_size {
            let leaf_proofs = self.leaf_proofs.drain(..self.leaf_batch_size).collect();
            self.push_internal_proofs(leaf_proofs);
        }
        let mut aggregator_ids: Vec<_> = self.sub_aggregators.keys().copied().collect();
        // Get the total number of proofs that need to be distributed amongst aggregators
        let mut pending_queue_size = self.internal_proofs.iter().map(|s| s.1.len()).sum::<usize>();
        // While there are still pending proofs, distribute them amongst aggregators
        while pending_queue_size > 0 {
            // Sort the aggregator starting with the least loaded one first
            aggregator_ids.sort_by(|x, y| {
                let x = &self.sub_aggregators[x];
                let y = &self.sub_aggregators[y];
                // Compare the queue size/throughput values
                (x.pending_queue_size() as f64 * y.proof_throughput())
                    .total_cmp(&(y.pending_queue_size() as f64 * x.proof_throughput()))
            });
            // Indicates whether an appropriate aggregator to do the work has been found
            let mut found = false;
            // Now try to place some pending proofs at the least loaded aggregator that can be saturated
            for id in &aggregator_ids {
                // Number of proofs required to saturate the aggregator
                let proof_throughput = self.sub_aggregators[id].proof_throughput() as usize * 2;
                // Only send the prefix of the queue if it can saturate this aggregator
                if pending_queue_size < proof_throughput { continue; }
                // Indicate that an aggregator has been found
                found = true;
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
                        let batch1_id = self.gen_batch_id();
                        let batch1 = batch.split_off(batch.len() / 2);
                        self.internal_proofs.push_front((batch1_id, batch1));
                        // Maintain a tree of proof dependencies
                        batch_id = self.gen_batch_id();
                        self.proof_parents.insert((self.aggregator_id, batch_id), qualified_batch_id);
                        self.proof_parents.insert((self.aggregator_id, batch1_id), qualified_batch_id);
                        self.proof_children.insert(qualified_batch_id, ((self.aggregator_id, batch_id), (self.aggregator_id, batch1_id)));
                        qualified_batch_id = (self.aggregator_id, batch_id);
                    }
                    // Add the drainage to the sub aggregator
                    total_chunk_size += batch.len();
                    let new_batch_id = self.sub_aggregators.get_mut(&id).unwrap().push_internal_proofs(batch);
                    let new_qualified_batch_id = (*id, new_batch_id);
                    // Replace the qualified batch ID with the new qualified batch ID
                    if let Some(parent) = self.proof_parents.remove(&qualified_batch_id) {
                        self.proof_parents.insert(new_qualified_batch_id, parent);
                        let children = self.proof_children.get_mut(&parent).unwrap();
                        if children.0 == qualified_batch_id {
                            children.0 = new_qualified_batch_id;
                        } else if children.1 == qualified_batch_id {
                            children.1 = new_qualified_batch_id;
                        }
                    } else {
                        self.proof_aliases.insert(new_qualified_batch_id, batch_id);
                    }
                }
                // Sending the prefix will reduce this aggregator's queue size
                pending_queue_size -= total_chunk_size;
                break;
            }
            // If an aggregator has not been found, then stop the distribution for now
            if !found { break; }
        }
        // Advance all the sub-aggregators
        for (aggregator_id, aggregator) in self.sub_aggregators.iter_mut() {
            aggregator.step();
            // Grab all the recursive proofs from this aggregator
            while let Some((batch_id, proof)) = aggregator.pop_recursive_proof() {
                self.sub_recursive_proofs.insert((*aggregator_id, batch_id), proof);
            }
        }
        // Finally, recombine all of the proofs from the sub-aggregators
        let mut proof_descendants = HashMap::new();
        for (qualified_id, _proof) in &self.sub_recursive_proofs {
            let mut qualified_id = *qualified_id;
            // A proof is a descendant of itself
            proof_descendants.insert(qualified_id, vec![qualified_id]);
            // Combine complete binary subtrees while it's possible
            while let Some(parent) = self.proof_parents.get(&qualified_id).copied() {
                let children = self.proof_children[&parent];
                match (proof_descendants.get(&children.0), proof_descendants.get(&children.1)) {
                    // Only combine complete subtrees
                    (Some(descendants0), Some(descendants1)) if descendants0.len() == descendants1.len() => {
                        // Remove the subtrees to ensure that recursive proving is not duplicated
                        let mut descendants0 = proof_descendants.remove(&children.0).unwrap();
                        let mut descendants1 = proof_descendants.remove(&children.1).unwrap();
                        self.proof_children.remove(&parent);
                        self.proof_parents.remove(&children.0);
                        self.proof_parents.remove(&children.1);
                        // Merge the descendants and store in preparation for a batch proof
                        descendants0.append(&mut descendants1);
                        proof_descendants.insert(parent, descendants0);
                        // Move to the parent
                        qualified_id = parent;
                    },
                    _ => break,
                }
            }
        }
        // Finally, create new batches to be recursively proved in future calls
        for (qualified_id, descendants) in proof_descendants {
            // Recombination is only required if there are multiple descendants
            if descendants.len() > 1 {
                // Grab the identified subproofs
                let proofs: Vec<_> = descendants
                    .into_iter()
                    .map(|x| self.sub_recursive_proofs.remove(&x).unwrap())
                    .collect();
                // And push them back into the queue
                assert_eq!(qualified_id.0, self.aggregator_id);
                self.internal_proofs.push_back((qualified_id.1, proofs));
            } else if let Some(alias) = self.proof_aliases.remove(&qualified_id) {
                // Move root proofs to the output queue
                let root_proof = self.sub_recursive_proofs.remove(&descendants[0]).unwrap();
                self.recursive_proofs.push_back((alias, root_proof));
            }
        }
    }
}

fn main() {
    println!("Hello, world!");
}
