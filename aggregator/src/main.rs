use std::collections::VecDeque;
use std::collections::HashMap;
use barretenberg_rs::generated_types::CircuitProveResponse;

/// Type alias to ease generic usage of aggregators
type AggregatorBox<A> = Box<dyn Aggregator<AggregatorId = <A as Aggregator>::AggregatorId, Proof = <A as Aggregator>::Proof>>;

/// The interface shared by all proof aggregators
trait Aggregator {
    /// The type that holds aggregator IDs
    type AggregatorId;
    /// The type that holds proofs
    type Proof;
    /// Push a leaf proof onto a queue of leaf proofs to aggregate
    fn push_leaf_proof(&mut self, proof: Self::Proof);
    /// Push a batch of proofs to aggregate onto a queue
    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>);
    /// Pop a recursive proof from the queue of aggregations
    fn pop_recursive_proof(&mut self) -> Option<Self::Proof>;
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
struct RecursiveAggregator {
    /// Minimum batch size that can be formed from leaf proofs
    pub leaf_batch_size: usize,
    /// Queue of leaf proofs to be aggregated
    pub leaf_proofs: VecDeque<CircuitProveResponse>,
    /// Queue of internal proofs to be aggregated
    pub internal_proofs: VecDeque<Vec<CircuitProveResponse>>,
    /// Queue of produced recursive proofs
    pub recursive_proofs: VecDeque<CircuitProveResponse>,
    /// Proof aggregators to offload work onto
    pub sub_aggregators: HashMap<u16, Box<dyn Aggregator<AggregatorId = u16, Proof = CircuitProveResponse>>>,
    /// The ID to assign to the next sub aggregator
    pub next_aggregator_id: u16,
}

impl Aggregator for RecursiveAggregator {
    type AggregatorId = u16;
    type Proof = CircuitProveResponse;
    
    fn push_leaf_proof(&mut self, proof: Self::Proof) {
        self.leaf_proofs.push_back(proof);
    }

    fn push_internal_proofs(&mut self, proofs: Vec<Self::Proof>) {
        // Batch sizes must be powers of two
        assert!(proofs.len().is_power_of_two());
        self.internal_proofs.push_back(proofs);
    }

    fn pop_recursive_proof(&mut self) -> Option<Self::Proof> {
        self.recursive_proofs.pop_front()
    }

    fn pending_queue_size(&self) -> usize {
        // Get the proofs queued in this aggregator
        let local = self.leaf_proofs.len() +
            self.internal_proofs.iter().map(|s| s.len()).sum::<usize>();
        // Get the proofs queued in the sub-aggregators
        let delegated: usize = self.sub_aggregators.values()
            .map(|agg| agg.pending_queue_size())
            .sum();
        // Return the total proofs queued
        local + delegated
    }

    fn proof_throughput(&self) -> f64 {
        // A recursive aggregator must have at least one child to process the proofs
        assert!(self.sub_aggregators.len() > 0);
        // The throughput of a recursive aggregator is the sum of those of its sub-aggregators
        let throughput = self.sub_aggregators.values().map(|x| x.proof_throughput()).sum();
        throughput
    }

    fn insert_sub_aggregator(&mut self, sub_aggregator: AggregatorBox<Self>) -> Self::AggregatorId {
        // Save the sub-aggregator with the given free ID
        let aggregator_id = self.next_aggregator_id;
        self.sub_aggregators.insert(aggregator_id, sub_aggregator);
        // Get the next available free ID
        self.next_aggregator_id += 1;
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
        let mut aggregator_ids: Vec<_> = self.sub_aggregators.keys().cloned().collect();
        // Get the total number of proofs that need to be distributed amongst aggregators
        let mut pending_queue_size = self.internal_proofs.iter().map(|s| s.len()).sum::<usize>();
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
                if pending_queue_size >= proof_throughput {
                    // Indicate that an aggregator has been found
                    found = true;
                    let mut total_chunk_size = 0;
                    // Take as many chunks as required to saturate the aggregator
                    while total_chunk_size < proof_throughput {
                        // Compute the amount that needs to be drained to saturate the current aggregator
                        let mut chunk = self.internal_proofs.pop_front().unwrap();
                        let target_size = std::cmp::min(proof_throughput.next_power_of_two(), chunk.len());
                        // Keep splitting of batches (that are powers of two) until we get to the correct size
                        while chunk.len() > target_size {
                            let rem = chunk.split_off(chunk.len() / 2);
                            // These remainder batches will be processed in future loops
                            self.internal_proofs.push_front(rem);
                        }
                        // And the drainage to the sub aggregator
                        total_chunk_size += chunk.len();
                        self.sub_aggregators.get_mut(&id).unwrap().push_internal_proofs(chunk);
                    }
                    // Sending the prefix will reduce this aggregator's queue size
                    pending_queue_size -= total_chunk_size;
                    break;
                }
            }
            // If an aggregator has not been found, then stop the distribution for now
            if !found { break; }
        }
        // Finally, advance all the sub-aggregators
        for aggregator in self.sub_aggregators.values_mut() {
            aggregator.step();
        }
    }
}

fn main() {
    println!("Hello, world!");
}
