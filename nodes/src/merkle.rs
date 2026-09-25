//! Implementation of a Merkle tree of commitments used to prove the existence of notes.

use borsh::{BorshDeserialize, BorshSerialize};
use core::convert::TryFrom;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::iter::repeat;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::Backend;
use crate::DIGEST_BYTES;
use acir::FieldElement;
use acir::AcirField;

const SAPLING_COMMITMENT_TREE_DEPTH: usize = crate::MAX_TREE_DEPTH;

/// A constant padding leaf used in Merkle trees.
/// This was computed from sha256("EMPTY")
const PADDING_LEAF: [u8; DIGEST_BYTES] = [
    0xcc, 0x1d, 0x2f, 0x83, 0x84, 0x45, 0xdb, 0x7a,
    0xec, 0x43, 0x1d, 0xf9, 0xee, 0x8a, 0x87, 0x1f,
    0x40, 0xe7, 0xaa, 0x5e, 0x06, 0x4f, 0xc0, 0x56,
    0x63, 0x3e, 0xf8, 0xc6, 0x0f, 0xab, 0x7b, 0x06
];
/// The above constant as a node. Note that nodes
/// internally represent numbers in big-endian byte
/// order.
const PADDING_LEAF_NODE: Node = Node { repr: [
    0x06, 0x7b, 0xab, 0x0f, 0xc6, 0xf8, 0x3e, 0x63,
    0x56, 0xc0, 0x4f, 0x06, 0x5e, 0xaa, 0xe7, 0x40,
    0x1f, 0x87, 0x8a, 0xee, 0xf9, 0x1d, 0x43, 0xec,
    0x7a, 0xdb, 0x45, 0x84, 0x83, 0x2f, 0x1d, 0xcc
] };

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath<Node> {
    pub auth_path: Vec<(Node, bool)>,
    pub position: u64,
}

/// A hashable node within a Merkle tree.
pub trait Hashable<Ctx>: Clone + Copy {
    /// Returns the parent node within the tree of the two given nodes.
    fn combine(_: &mut Ctx, _: usize, _: &Self, _: &Self) -> Self;

    /// Returns a blank leaf node.
    fn empty_leaf() -> Self;

    /// Returns the empty root for the given depth.
    fn empty_root(_: &mut Ctx, _: &mut Vec<Self>, _: usize) -> Self;
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Default, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Node {
    // Big endian representation of node
    repr: [u8; 32],
}

impl Node {
    pub fn new(mut repr: [u8; 32]) -> Self {
        repr.reverse();
        Self::from_scalar(&FieldElement::from_be_bytes_reduce(&repr))
    }

    /// Convert this node into its byte vector representation.
    pub const fn into_repr(mut self) -> [u8; 32] {
        self.repr.reverse();
        self.repr
    }

    /// Constructs a new note commitment tree node from a [`bls12_381::Scalar`]
    pub fn from_scalar(cmu: &FieldElement) -> Self {
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&cmu.to_be_bytes());
        Self { repr }
    }

    /// Converts the node to a scalar
    pub fn into_scalar(self) -> FieldElement {
        FieldElement::from_be_bytes_reduce(&self.repr)
    }
}

impl<B: Backend> Hashable<BarretenbergApi<B>> for Node {
    fn empty_leaf() -> Self {
        PADDING_LEAF_NODE
    }

    fn combine(api: &mut BarretenbergApi<B>, _level: usize, lhs: &Self, rhs: &Self) -> Self {
        // Use Barretenberg to compute Poseidon hash
        let repr = api
            .poseidon2_hash(vec![lhs.repr.to_vec(), rhs.repr.to_vec()])
            .expect("unable to compute Poseidon hash")
            .hash
            .try_into()
            .expect("malformed Poseidon hash");
        Node { repr }
    }

    fn empty_root(api: &mut BarretenbergApi<B>, cache: &mut Vec<Self>, level: usize) -> Self {
        // Initialize the cache
        if cache.is_empty() {
            cache.push(<Self as Hashable<BarretenbergApi<B>>>::empty_leaf());
        }
        // Expand the cache enough
        for i in cache.len()-1..level {
            let next = Self::combine(api, i, &cache[i], &cache[i]);
            cache.push(next);
        }
        // Return the requested level
        cache[level]
    }
}

/// An immutable commitment tree
#[derive(Clone, Debug, Default)]
pub struct CommitmentTree<Node> {
    // All nodes of the tree, level-by-level
    nodes: Vec<Node>,
    // Number of leafs in the Merkle tree
    leaf_count: usize,
    // Cache of empty hashes at each depth
    cache: Vec<Node>,
}

impl<Node: Clone> CommitmentTree<Node> {
    /// Construct a commitment tree with the given leaf nodes
    pub fn new<T>(api: &mut T, leafs: &[Node]) -> Self where Node: Hashable<T> {
        // This capacity is sufficient to hold a Merkle tree (where an empty node
        // is added onto some rows to ensure that they are of even size) with the
        // given number of leaves. This follows from the identity ceil(ceil(x/m)/n)=ceil(x/(mn))
        let mut tree = Vec::with_capacity(leafs.len() * 2 + SAPLING_COMMITMENT_TREE_DEPTH - 1);
        tree.extend_from_slice(leafs);
        // Infer the rest of the tree
        Self::complete(api, tree, 0, leafs.len(), 0, leafs.len())
    }
    /// Merge the n-1 full Merkle trees with the last possibly unfilled one. All
    /// full trees must have the same size which must be a power of 2 and the
    /// tree must be smaller than this size.
    pub fn merge<T>(api: &mut T, subtrees: &[CommitmentTree<Node>]) -> Self where Node: Hashable<T> {
        if subtrees.is_empty() {
            return Self { nodes: Vec::new(), leaf_count: 0, cache: Vec::new() };
        } else if subtrees.len() == 1 {
            return subtrees[0].clone();
        }
        let size = subtrees[0].size();
        assert!(size.is_power_of_two());
        for subtree in subtrees.iter().rev().skip(1) {
            assert_eq!(subtree.size(), size);
        }
        // Combine the 1 or more supplied subtrees
        let mut height = 0;
        let mut prev_first_start = 0;
        let mut prev_first_width = subtrees[0].size();
        let mut prev_last_start = 0;
        let mut prev_last_width = subtrees.last().unwrap().size();
        let mut prev_start = 0;
        let mut prev_width = (subtrees.len() - 1) * prev_first_width + prev_last_width;
        let leafs = prev_width;
        let mut tree = Vec::with_capacity(leafs * 2 + SAPLING_COMMITMENT_TREE_DEPTH - 1);
        loop {
            // Need to make sure that right child is present for parent
            if prev_last_width % 2 == 1 && prev_first_width > 1 {
                prev_last_width += 1;
                prev_width += 1;
            }
            // Combine all the rows at the current level
            for subtree in &subtrees[0..(subtrees.len() - 1)] {
                tree.extend_from_slice(
                    &subtree.nodes[prev_first_start..(prev_first_start + prev_first_width)],
                );
            }
            tree.extend_from_slice(
                &subtrees.last().unwrap().nodes[prev_last_start..(prev_last_start + prev_last_width)],
            );
            // Quit when we are the top of the full trees
            if prev_first_width == 1 {
                break;
            }
            // Update our positions on the full and unfull trees
            prev_first_start += prev_first_width;
            prev_first_width /= 2;
            prev_last_start += prev_last_width;
            prev_last_width /= 2;
            prev_start += prev_width;
            prev_width /= 2;
            height += 1;
        }
        // Now that we have taken as many levels as possible from the
        // supplied subtrees, infer the rest
        Self::complete(api, tree, prev_start, prev_width, height, leafs)
    }
    /// Complete the construction of given Merkle tree given the highest row data
    fn complete<T>(
        api: &mut T,
        mut tree: Vec<Node>,
        mut prev_start: usize,
        mut prev_width: usize,
        heightp: usize,
        leafs: usize,
    ) -> Self where Node: Hashable<T> {
        // A cache for empty roots
        let mut cache = Vec::new();
        // Add higher and higher rows of the Merkle tree
        for height in heightp..SAPLING_COMMITMENT_TREE_DEPTH {
            if prev_width % 2 == 1 {
                // Add a dummy for the right-most parent's right child
                prev_width += 1;
                tree.push(Node::empty_root(api, &mut cache, height))
            }
            for j in 0..(prev_width / 2) {
                // Add the nodes of the next row dependent upon previous row
                let comb = Node::combine(
                    api,
                    height,
                    &tree[prev_start + 2 * j],
                    &tree[prev_start + 2 * j + 1],
                );
                tree.push(comb);
            }
            // Next row will be adjacent to current row in vector
            prev_start += prev_width;
            prev_width /= 2;
        }
        Self { nodes: tree, leaf_count: leafs, cache }
    }
    /// Get the root node of the commitment tree
    pub fn root<T>(&mut self, api: &mut T) -> Node where Node: Hashable<T> {
        self.nodes
            .last()
            .cloned()
            .unwrap_or_else(|| Node::empty_root(api, &mut self.cache, SAPLING_COMMITMENT_TREE_DEPTH))
    }
    /// Construct a merkle path to the given position in commitment tree
    pub fn path<T>(&mut self, api: &mut T, mut pos: usize) -> MerklePath<Node> where Node: Hashable<T> {
        let mut path = MerklePath {
            auth_path: vec![],
            position: pos as u64,
        };
        let mut start = 0;
        let mut width = self.leaf_count;

        for height in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            if width % 2 == 1 {
                width += 1;
            }
            if pos % 2 == 0 {
                // The current node is a left child
                let node = if pos + 1 < width {
                    // Node is within current row
                    self.nodes[start + pos + 1]
                } else {
                    // Node is to the right of current row
                    Node::empty_root(api, &mut self.cache, height)
                };
                path.auth_path.push((node, false));
            } else {
                // The current node is a right child
                let node = if pos - 1 < width {
                    self.nodes[start + pos - 1]
                } else {
                    Node::empty_root(api, &mut self.cache, height)
                };
                path.auth_path.push((node, true));
            }
            // Move to the parent of the current node
            start += width;
            width /= 2;
            pos /= 2;
        }
        path
    }
    /// Returns the number of leaf nodes in the tree.
    pub fn size(&self) -> usize {
        self.leaf_count
    }
}

impl<Node: BorshSerialize> BorshSerialize for CommitmentTree<Node> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        (&self.nodes, self.leaf_count).serialize(writer)
    }
}

impl<Node: BorshDeserialize> BorshDeserialize for CommitmentTree<Node> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let tup: (Vec<Node>, usize) = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self { nodes: tup.0, leaf_count: tup.1, cache: Default::default() })
    }
}
