use barretenberg_rs::BarretenbergError;
use barretenberg_rs::Backend;
use std::collections::BTreeSet;
use crate::merkle::CmtNode;
use crate::merkle::CommitmentTree;
use crate::types::Nullifier;
use borsh::{BorshSerialize, BorshDeserialize};
use crate::Transaction;
use std::collections::BTreeMap;
use barretenberg_rs::BarretenbergApi;
use nodes::BarretenbergCircuit;
use crate::types::MAX_TREE_DEPTH;
use acir::FieldElement;
use alloy::primitives::keccak256;
use acir::AcirField;
use crate::merkle::ActNode;
use barretenberg_rs::GrumpkinPoint;
use barretenberg_rs::generated_types::CircuitProveResponse;

#[derive(Debug)]
// Reasons why a transaction might be rejected
pub enum ShieldedPoolError {
    BarretenbergError(BarretenbergError),
    LogicProof,
    ComplianceProof,
    DuplicateNullifier,
    DuplicateCommitment,
    UnpairedNullifier,
    UnpairedCommitment,
    CircuitNotRegistered,
    NonExistentAnchor,
    InvalidActionTreeRoot,
    InvalidSignature,
}

// State of the shielded pool
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ShieldedPool {
    // Nullifiers in the pool
    pub nullifiers: BTreeSet<Nullifier>,
    // Resource commitments in the pool
    commitments: Vec<CmtNode>,
    // Transactions in the pool
    pub transactions: Vec<Transaction>,
    // Historical anchors
    anchors: BTreeSet<CmtNode>,
    // Registered logic circuits
    #[borsh(skip)]
    logic_circuits: BTreeMap<Vec<u8>, BarretenbergCircuit>,
}

impl ShieldedPool {
    pub fn new<B: Backend>(api: &mut BarretenbergApi<B>) -> Self {
        // Include an anchor for the empty tree
        let mut anchors = BTreeSet::default();
        anchors.insert(CommitmentTree::new(api, MAX_TREE_DEPTH, &[]).root(api));
        ShieldedPool {
            anchors,
            nullifiers: BTreeSet::default(),
            commitments: Vec::default(),
            transactions: Vec::default(),
            logic_circuits: BTreeMap::default(),
        }
    }
    
    pub fn register_logic(&mut self, logic_circuit: BarretenbergCircuit) {
        self.logic_circuits.insert(logic_circuit.compute_vk_response.hash.clone(), logic_circuit);
    }

    pub fn deregister_logic(&mut self, logic_hash: Vec<u8>) -> Option<BarretenbergCircuit> {
        self.logic_circuits.remove(&logic_hash)
    }
    
    pub fn submit<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        compliance_circuit: &mut BarretenbergCircuit,
        mut tx: Transaction,
    ) -> Result<(), ShieldedPoolError> {
        // Verify the transaction signature
        let signature = tx.signature.take().expect("transaction must be signed");
        let tx_bytes = borsh::to_vec(&tx).expect("unable to hash transaction");
        let tx_hash = keccak256(tx_bytes);
        let msg = FieldElement::from_le_bytes_reduce(&tx_hash.0);
        let public_key = GrumpkinPoint {
            x: tx.compliance_instance.delta.x.to_be_bytes(),
            y: tx.compliance_instance.delta.y.to_be_bytes(),
        };
        let verified = api.schnorr_verify_signature(&msg.to_be_bytes(), public_key, &signature.0, &signature.1)
            .expect("unable to verify transaction signature");
        println!("Signature verification response: {:?}", verified);
        if !verified.verified {
            return Err(ShieldedPoolError::InvalidSignature);
        }
        // Compute the expected action tree root
        let mut tags = vec![];
        for i in 0..tx.compliance_instance.consumed_count {
            tags.push(ActNode(tx.compliance_instance.consumed_publics[i as usize].resource_nullifier));
        }
        for i in 0..tx.compliance_instance.created_count {
            tags.push(ActNode(tx.compliance_instance.created_publics[i as usize].resource_commitment));
        }
        let action_tree_depth = if tags.len() == 1 {
            0
        } else {
            (tags.len() - 1).ilog2() as usize + 1
        };
        let action_root = CommitmentTree::new(&mut (), action_tree_depth, &tags).root(&mut ());
        // Check the supplied action roots
        for (logic_instance, _proof) in &tx.logic_instances {
            if tags.contains(&ActNode(logic_instance.tag)) {
                if logic_instance.action_root != action_root.0 {
                    return Err(ShieldedPoolError::InvalidActionTreeRoot)
                }
            }
        }
        // Check the compliance proof
        let compliance_prove_response = CircuitProveResponse {
            proof: tx.compliance_proof.clone(),
            public_inputs: vec![tx.compliance_instance.digest().to_be_bytes()],
            vk: compliance_circuit.compute_vk_response.clone(),
        };
        let compliance_verify_response = compliance_circuit
            .circuit_verify(api, compliance_prove_response.clone())
            .map_err(ShieldedPoolError::BarretenbergError)?;
        println!("Compliance proof verification response: {:?}", compliance_verify_response);
        if !compliance_verify_response.verified {
            return Err(ShieldedPoolError::ComplianceProof);
        }
        let mut nullifiers = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        // Track the nullifiers encountered
        for i in 0..tx.compliance_instance.consumed_count {
            let consumed_public = tx.compliance_instance.consumed_publics[i as usize];
            if nullifiers.contains_key(&consumed_public.resource_nullifier) {
                return Err(ShieldedPoolError::DuplicateNullifier);
            } else if !self.anchors.contains(&CmtNode::new(consumed_public.commitment_tree_root)) {
                return Err(ShieldedPoolError::NonExistentAnchor);
            } else {
                nullifiers.insert(consumed_public.resource_nullifier, consumed_public.resource_logic_ref);
            }
        }
        // Track the commitments encountered
        for i in 0..tx.compliance_instance.created_count {
            let created_public = tx.compliance_instance.created_publics[i as usize];
            if commitments.contains_key(&created_public.resource_commitment) {
                return Err(ShieldedPoolError::DuplicateCommitment);
            } else {
                commitments.insert(created_public.resource_commitment, created_public.resource_logic_ref);
            }
        }
        // Check all the logic proofs
        for (logic_instance, proof) in &tx.logic_instances {
            // Cross-check the tags and grab the relevant circuit
            let logic_circuit = if logic_instance.is_consumed {
                // Cross-check the nullifiers
                if let Some(hash) = nullifiers.remove(&logic_instance.tag) {
                    self.logic_circuits.get_mut(&hash.to_vec()).ok_or(ShieldedPoolError::CircuitNotRegistered)?
                } else {
                    return Err(ShieldedPoolError::UnpairedNullifier);
                }
            } else {
                // Cross-check the commitments
                if let Some(hash) = commitments.remove(&logic_instance.tag) {
                    self.logic_circuits.get_mut(&hash.to_vec()).ok_or(ShieldedPoolError::CircuitNotRegistered)?
                } else {
                    return Err(ShieldedPoolError::UnpairedCommitment);
                }
            };
            // Verify the proofs
            let prove_response = CircuitProveResponse {
                proof: proof.clone(),
                public_inputs: vec![logic_instance.digest().to_be_bytes()],
                vk: logic_circuit.compute_vk_response.clone(),
            };
            let verify_response = logic_circuit
                .circuit_verify(api, prove_response.clone())
                .map_err(ShieldedPoolError::BarretenbergError)?;
            println!("Logic proof verification response: {:?}", verify_response);
            if !verify_response.verified {
                return Err(ShieldedPoolError::LogicProof);
            }
        }
        // Ensure that there's a logic instance for each tag in the compliance instance
        if !nullifiers.is_empty() {
            return Err(ShieldedPoolError::UnpairedNullifier);
        } else if !commitments.is_empty() {
            return Err(ShieldedPoolError::UnpairedCommitment);
        }
        // Update the nullifier set
        for (logic_instance, _proof) in &tx.logic_instances {
            if logic_instance.is_consumed {
                // Handle nullification
                if self.nullifiers.contains(&logic_instance.tag) {
                    return Err(ShieldedPoolError::DuplicateNullifier);
                } else {
                    self.nullifiers.insert(logic_instance.tag);
                }
            } else {
                // Update the Merkle tree
                self.commitments.push(CmtNode::new(logic_instance.tag));
            }
        }
        // Compute the new Merkle root
        self.anchors.insert(CommitmentTree::new(api, MAX_TREE_DEPTH, &self.commitments).root(api));
        // Record the transaction
        self.transactions.push(tx);
        Ok(())
    }
}
