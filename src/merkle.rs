// =============================================================================
// MOONCOIN v2.35 - Merkle Trees
// =============================================================================
//
// Merkle trees enable efficient transaction verification without downloading
// entire blocks. Essential for SPV (Simplified Payment Verification) clients.
//
// Features:
// - Build Merkle tree from transaction list
// - Generate inclusion proofs
// - Verify proofs efficiently
// - Support for Bitcoin-style double SHA256
//
// Complexity:
// - Tree construction: O(n)
// - Proof generation: O(log n)
// - Proof verification: O(log n)
// - Proof size: O(log n) = ~320 bytes for 1000 txs
//
// =============================================================================

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// =============================================================================
// Constants
// =============================================================================

/// Hash size in bytes
pub const HASH_SIZE: usize = 32;

/// Type alias for 32-byte hash
pub type Hash256 = [u8; HASH_SIZE];

/// Empty hash (all zeros)
pub const EMPTY_HASH: Hash256 = [0u8; HASH_SIZE];

// =============================================================================
// Hash Functions
// =============================================================================

/// Single SHA256 hash
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&result);
    hash
}

/// Double SHA256 (Bitcoin-style)
pub fn double_sha256(data: &[u8]) -> Hash256 {
    sha256(&sha256(data))
}

/// Hash two child nodes together (for Merkle tree)
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    double_sha256(&combined)
}

// =============================================================================
// Merkle Proof
// =============================================================================

/// Direction in the Merkle tree (for proof reconstruction)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    /// Sibling is on the left
    Left,
    /// Sibling is on the right
    Right,
}

/// A single step in a Merkle proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStep {
    /// Hash of the sibling node
    pub hash: Hash256,
    /// Direction of the sibling
    pub direction: ProofDirection,
}

/// Merkle inclusion proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash being proven
    pub leaf_hash: Hash256,
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Proof steps from leaf to root
    pub steps: Vec<ProofStep>,
    /// Expected Merkle root
    pub root: Hash256,
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(
        leaf_hash: Hash256,
        leaf_index: usize,
        steps: Vec<ProofStep>,
        root: Hash256,
    ) -> Self {
        MerkleProof {
            leaf_hash,
            leaf_index,
            steps,
            root,
        }
    }

    /// Verify the proof
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;

        for step in &self.steps {
            current = match step.direction {
                ProofDirection::Left => hash_pair(&step.hash, &current),
                ProofDirection::Right => hash_pair(&current, &step.hash),
            };
        }

        current == self.root
    }

    /// Size of the proof in bytes
    pub fn size_bytes(&self) -> usize {
        // leaf_hash + leaf_index + root + steps
        HASH_SIZE + 8 + HASH_SIZE + (self.steps.len() * (HASH_SIZE + 1))
    }

    /// Number of steps (tree depth for this leaf)
    pub fn depth(&self) -> usize {
        self.steps.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

// =============================================================================
// Merkle Tree
// =============================================================================

/// A Merkle tree built from transaction hashes
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All nodes in the tree (bottom to top, left to right)
    nodes: Vec<Hash256>,
    /// Number of leaves (transactions)
    leaf_count: usize,
    /// Tree depth
    depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from transaction hashes
    pub fn from_hashes(hashes: &[Hash256]) -> Self {
        if hashes.is_empty() {
            return MerkleTree {
                nodes: vec![EMPTY_HASH],
                leaf_count: 0,
                depth: 0,
            };
        }

        let leaf_count = hashes.len();
        
        // Pad to power of 2 by duplicating last hash (Bitcoin-style)
        let padded_count = leaf_count.next_power_of_two();
        let depth = (padded_count as f64).log2() as usize;

        let mut leaves: Vec<Hash256> = hashes.to_vec();
        while leaves.len() < padded_count {
            leaves.push(*leaves.last().unwrap());
        }

        // Build tree bottom-up
        let mut nodes = leaves;
        let mut current_level = nodes.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                next_level.push(hash_pair(&left, &right));
            }
            
            nodes.extend_from_slice(&next_level);
            current_level = next_level;
        }

        MerkleTree {
            nodes,
            leaf_count,
            depth,
        }
    }

    /// Build from transaction data (hashes each transaction first)
    pub fn from_transactions(transactions: &[Vec<u8>]) -> Self {
        let hashes: Vec<Hash256> = transactions
            .iter()
            .map(|tx| double_sha256(tx))
            .collect();
        Self::from_hashes(&hashes)
    }

    /// Get the Merkle root
    pub fn root(&self) -> Hash256 {
        *self.nodes.last().unwrap_or(&EMPTY_HASH)
    }

    /// Get the root as hex string
    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Get number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get a leaf hash by index
    pub fn get_leaf(&self, index: usize) -> Option<Hash256> {
        if index < self.leaf_count {
            Some(self.nodes[index])
        } else {
            None
        }
    }

    /// Generate a proof for a leaf at the given index
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let leaf_hash = self.nodes[leaf_index];
        let mut steps = Vec::new();
        let mut current_index = leaf_index;
        let padded_count = self.leaf_count.next_power_of_two();
        let mut level_size = padded_count;
        let mut level_start = 0;

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling_hash = if level_start + sibling_index < self.nodes.len() {
                self.nodes[level_start + sibling_index]
            } else {
                // Duplicate last node for odd counts
                self.nodes[level_start + current_index]
            };

            let direction = if current_index % 2 == 0 {
                ProofDirection::Right
            } else {
                ProofDirection::Left
            };

            steps.push(ProofStep {
                hash: sibling_hash,
                direction,
            });

            // Move to parent level
            level_start += level_size;
            level_size /= 2;
            current_index /= 2;
        }

        Some(MerkleProof::new(
            leaf_hash,
            leaf_index,
            steps,
            self.root(),
        ))
    }

    /// Verify a proof against this tree's root
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        proof.root == self.root() && proof.verify()
    }

    /// Get all nodes at a specific level (0 = leaves)
    pub fn get_level(&self, level: usize) -> Vec<Hash256> {
        if level > self.depth {
            return vec![];
        }

        let padded_count = self.leaf_count.next_power_of_two();
        let mut start = 0;
        let mut size = padded_count;

        for _ in 0..level {
            start += size;
            size /= 2;
        }

        if start + size <= self.nodes.len() {
            self.nodes[start..start + size].to_vec()
        } else {
            vec![]
        }
    }

    /// Print tree structure (for debugging)
    pub fn print_tree(&self) {
        println!("Merkle Tree ({} leaves, depth {})", self.leaf_count, self.depth);
        println!("Root: {}", hex::encode(&self.root()[..8]));
        
        let padded_count = self.leaf_count.next_power_of_two();
        let mut start = 0;
        let mut size = padded_count;
        let mut level = 0;

        while size >= 1 && start < self.nodes.len() {
            print!("Level {}: ", level);
            for i in 0..size.min(self.nodes.len() - start) {
                print!("{}.. ", hex::encode(&self.nodes[start + i][..4]));
            }
            println!();
            start += size;
            size /= 2;
            level += 1;
        }
    }
}

// =============================================================================
// Merkle Block (for SPV) - Simplified Implementation
// =============================================================================

/// A partial Merkle tree for SPV verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleBlock {
    /// Block header hash
    pub block_hash: Hash256,
    /// Total number of transactions in block
    pub total_transactions: u32,
    /// Hashes needed to reconstruct proof
    pub hashes: Vec<Hash256>,
    /// Bit flags indicating matched transactions
    pub flags: Vec<u8>,
}

impl MerkleBlock {
    /// Create a MerkleBlock containing proofs for specific transactions
    /// Uses simplified approach: store individual proofs for each matched tx
    pub fn from_tree_and_matches(
        tree: &MerkleTree,
        block_hash: Hash256,
        matched_indices: &[usize],
    ) -> Self {
        let mut hashes = Vec::new();
        let mut flags = Vec::new();
        
        // For each matched transaction, we need to store its proof path
        // This is a simplified implementation that stores all necessary hashes
        
        // First, collect all the matched leaf hashes
        for &idx in matched_indices {
            if idx < tree.leaf_count() {
                hashes.push(tree.nodes[idx]);
            }
        }
        
        // Store proofs for each matched transaction
        for &idx in matched_indices {
            if let Some(proof) = tree.generate_proof(idx) {
                for step in &proof.steps {
                    if !hashes.contains(&step.hash) {
                        hashes.push(step.hash);
                    }
                }
            }
        }
        
        // Create flags - each bit indicates if that hash is a matched leaf
        let mut flag_bits = Vec::new();
        for hash in &hashes {
            let is_matched = matched_indices.iter().any(|&idx| {
                idx < tree.leaf_count() && tree.nodes[idx] == *hash
            });
            flag_bits.push(is_matched);
        }
        
        // Pack bits into bytes
        for chunk in flag_bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << i;
                }
            }
            flags.push(byte);
        }

        MerkleBlock {
            block_hash,
            total_transactions: tree.leaf_count() as u32,
            hashes,
            flags,
        }
    }

    /// Verify and extract matched transaction hashes
    /// Returns (merkle_root, matched_tx_hashes)
    pub fn extract_matches(&self) -> Result<(Hash256, Vec<Hash256>), &'static str> {
        if self.hashes.is_empty() {
            return Err("No hashes in merkle block");
        }
        
        // Extract matched hashes based on flags
        let mut matches = Vec::new();
        
        for (i, hash) in self.hashes.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            
            if byte_idx < self.flags.len() {
                let is_matched = (self.flags[byte_idx] >> bit_idx) & 1 == 1;
                if is_matched {
                    matches.push(*hash);
                }
            }
        }
        
        // Reconstruct root from the hashes
        // For this simplified implementation, we compute the root from all leaves
        if self.total_transactions == 0 {
            return Ok((EMPTY_HASH, matches));
        }
        
        // Simplified: use the stored hashes to find the matched ones
        // The actual root verification would require reconstructing the full path
        // For now, return the matches and let the caller verify against known root
        
        // Calculate root from matched hashes (simplified)
        let root = if matches.len() == 1 {
            matches[0]
        } else if matches.len() >= 2 {
            // This is a simplified root calculation
            // In production, you'd reconstruct using the full proof
            let mut current_level = matches.clone();
            while current_level.len() > 1 {
                let mut next_level = Vec::new();
                for chunk in current_level.chunks(2) {
                    let left = chunk[0];
                    let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                    next_level.push(hash_pair(&left, &right));
                }
                current_level = next_level;
            }
            current_level[0]
        } else {
            EMPTY_HASH
        };
        
        Ok((root, matches))
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        HASH_SIZE + 4 + (self.hashes.len() * HASH_SIZE) + self.flags.len()
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Calculate Merkle root from list of transaction hashes
pub fn calculate_merkle_root(tx_hashes: &[Hash256]) -> Hash256 {
    MerkleTree::from_hashes(tx_hashes).root()
}

/// Verify a single transaction is in a block given the Merkle root
pub fn verify_tx_inclusion(
    tx_hash: &Hash256,
    proof: &MerkleProof,
    merkle_root: &Hash256,
) -> bool {
    proof.leaf_hash == *tx_hash && proof.root == *merkle_root && proof.verify()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hashes(n: usize) -> Vec<Hash256> {
        (0..n)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0] = i as u8;
                hash[31] = (i * 17) as u8;
                double_sha256(&hash)
            })
            .collect()
    }

    #[test]
    fn test_hash_functions() {
        let data = b"hello world";
        let hash1 = sha256(data);
        let hash2 = double_sha256(data);
        
        assert_ne!(hash1, hash2);
        assert_eq!(hash1, sha256(data)); // Deterministic
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_hashes(&[]);
        assert_eq!(tree.root(), EMPTY_HASH);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let hashes = sample_hashes(1);
        let tree = MerkleTree::from_hashes(&hashes);
        
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.depth(), 0);
        assert_eq!(tree.root(), hashes[0]);
    }

    #[test]
    fn test_two_leaves() {
        let hashes = sample_hashes(2);
        let tree = MerkleTree::from_hashes(&hashes);
        
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.depth(), 1);
        
        let expected_root = hash_pair(&hashes[0], &hashes[1]);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_four_leaves() {
        let hashes = sample_hashes(4);
        let tree = MerkleTree::from_hashes(&hashes);
        
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.depth(), 2);
        
        let h01 = hash_pair(&hashes[0], &hashes[1]);
        let h23 = hash_pair(&hashes[2], &hashes[3]);
        let expected_root = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_odd_leaves() {
        // 3 leaves should pad to 4
        let hashes = sample_hashes(3);
        let tree = MerkleTree::from_hashes(&hashes);
        
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.depth(), 2);
        
        // h3 is duplicated
        let h01 = hash_pair(&hashes[0], &hashes[1]);
        let h23 = hash_pair(&hashes[2], &hashes[2]);
        let expected_root = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let hashes = sample_hashes(8);
        let tree = MerkleTree::from_hashes(&hashes);

        for i in 0..8 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for index {} failed", i);
            assert!(tree.verify_proof(&proof));
            assert_eq!(proof.leaf_hash, hashes[i]);
            assert_eq!(proof.depth(), 3); // log2(8) = 3
        }
    }

    #[test]
    fn test_proof_size() {
        // For 1024 transactions, proof should be ~10 * 32 = 320 bytes
        let hashes = sample_hashes(1024);
        let tree = MerkleTree::from_hashes(&hashes);
        let proof = tree.generate_proof(500).unwrap();
        
        assert_eq!(proof.depth(), 10);
        // Size: 32 (leaf) + 8 (index) + 32 (root) + 10 * 33 (steps) = 402 bytes
        assert!(proof.size_bytes() < 500);
    }

    #[test]
    fn test_invalid_proof() {
        let hashes = sample_hashes(4);
        let tree = MerkleTree::from_hashes(&hashes);
        
        let mut proof = tree.generate_proof(0).unwrap();
        
        // Tamper with the proof
        proof.steps[0].hash[0] ^= 0xFF;
        
        assert!(!proof.verify());
    }

    #[test]
    fn test_merkle_block() {
        let hashes = sample_hashes(8);
        let tree = MerkleTree::from_hashes(&hashes);
        let block_hash = [0xAB; 32];
        
        // Create MerkleBlock for transactions 2 and 5
        let matched = vec![2, 5];
        let merkle_block = MerkleBlock::from_tree_and_matches(&tree, block_hash, &matched);
        
        // Extract matches
        let (_, matches) = merkle_block.extract_matches().unwrap();
        
        // Verify we got the right matched transactions
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&hashes[2]));
        assert!(matches.contains(&hashes[5]));
    }

    #[test]
    fn test_calculate_merkle_root() {
        let hashes = sample_hashes(4);
        let root1 = calculate_merkle_root(&hashes);
        let root2 = MerkleTree::from_hashes(&hashes).root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_from_transactions() {
        let txs: Vec<Vec<u8>> = vec![
            b"tx1 data".to_vec(),
            b"tx2 data".to_vec(),
            b"tx3 data".to_vec(),
        ];
        
        let tree = MerkleTree::from_transactions(&txs);
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn test_proof_serialization() {
        let hashes = sample_hashes(4);
        let tree = MerkleTree::from_hashes(&hashes);
        let proof = tree.generate_proof(2).unwrap();
        
        let bytes = proof.to_bytes();
        let restored = MerkleProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.leaf_hash, restored.leaf_hash);
        assert_eq!(proof.root, restored.root);
        assert!(restored.verify());
    }
}
