//! A 64-level sparse Merkle tree over the Core's monotonic u64 loan IDs.
//! The Core, not a transaction submitter, constructs each loan payload digest.
#![forbid(unsafe_code)]

pub type Hash = [u8; 32];
pub const DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeKey {
    /// Zero is a leaf; 64 is the root.
    pub height: u8,
    pub index: u64,
}

/// A store is scoped to one broker and one deployment; callers prefix keys accordingly.
pub trait NodeStore {
    fn get(&self, key: NodeKey) -> Option<Hash>;
    fn set(&mut self, key: NodeKey, value: Hash);
    fn remove(&mut self, key: NodeKey);
}

pub trait HashFunction {
    /// Implement with SHA-256. NEAR callers use env::sha256_array.
    fn sha256(bytes: &[u8]) -> Hash;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    StaleLeaf,
    StaleRoot,
}

pub struct Book<H: HashFunction> {
    domain: Hash,
    empty: [Hash; DEPTH + 1],
    hash: core::marker::PhantomData<H>,
}

impl<H: HashFunction> Book<H> {
    /// Domain must identify protocol version, network, Core, asset and broker.
    pub fn new(domain: Hash) -> Self {
        let mut empty = [[0; 32]; DEPTH + 1];
        empty[0] = hash_parts::<H>(b"NCL/BOOK/EMPTY/v1", &domain, &[]);
        for height in 1..=DEPTH {
            empty[height] = branch::<H>(
                &domain,
                height as u8,
                &empty[height - 1],
                &empty[height - 1],
            );
        }
        Self {
            domain,
            empty,
            hash: core::marker::PhantomData,
        }
    }

    pub fn empty_root(&self) -> Hash {
        self.empty[DEPTH]
    }

    /// Bind a complete canonical loan-record digest to its immutable loan ID.
    pub fn leaf_hash(&self, loan_id: u64, payload_digest: &Hash) -> Hash {
        hash_parts::<H>(
            b"NCL/BOOK/LEAF/v1",
            &self.domain,
            &[&loan_id.to_le_bytes(), payload_digest],
        )
    }

    pub fn root<S: NodeStore>(&self, store: &S) -> Hash {
        store
            .get(NodeKey {
                height: DEPTH as u8,
                index: 0,
            })
            .unwrap_or(self.empty_root())
    }

    pub fn proof<S: NodeStore>(&self, store: &S, loan_id: u64) -> [Hash; DEPTH] {
        let mut siblings = [[0; 32]; DEPTH];
        let mut index = loan_id;
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = store
                .get(NodeKey {
                    height: height as u8,
                    index: index ^ 1,
                })
                .unwrap_or(self.empty[height]);
            index >>= 1;
        }
        siblings
    }

    pub fn verify(
        &self,
        loan_id: u64,
        leaf: Option<Hash>,
        siblings: &[Hash; DEPTH],
        expected_root: &Hash,
    ) -> bool {
        self.fold(loan_id, leaf.unwrap_or(self.empty[0]), siblings) == *expected_root
    }

    /// Verify the old path before writing; one update uses exactly 65 node slots.
    /// Removing a record is appropriate only when the Core retains its required tombstone.
    pub fn update<S: NodeStore>(
        &self,
        store: &mut S,
        loan_id: u64,
        expected_leaf: Option<Hash>,
        next_leaf: Option<Hash>,
        expected_root: &Hash,
    ) -> Result<Hash, Error> {
        let leaf_key = NodeKey {
            height: 0,
            index: loan_id,
        };
        if store.get(leaf_key).unwrap_or(self.empty[0]) != expected_leaf.unwrap_or(self.empty[0]) {
            return Err(Error::StaleLeaf);
        }
        let siblings = self.proof(store, loan_id);
        if !self.verify(loan_id, expected_leaf, &siblings, expected_root)
            || self.root(store) != *expected_root
        {
            return Err(Error::StaleRoot);
        }
        let mut index = loan_id;
        let mut current = next_leaf.unwrap_or(self.empty[0]);
        write_or_remove(store, leaf_key, current, self.empty[0]);
        for (height, sibling) in siblings.iter().enumerate() {
            current = if index & 1 == 0 {
                branch::<H>(&self.domain, (height + 1) as u8, &current, sibling)
            } else {
                branch::<H>(&self.domain, (height + 1) as u8, sibling, &current)
            };
            index >>= 1;
            write_or_remove(
                store,
                NodeKey {
                    height: (height + 1) as u8,
                    index,
                },
                current,
                self.empty[height + 1],
            );
        }
        Ok(current)
    }

    fn fold(&self, loan_id: u64, leaf: Hash, siblings: &[Hash; DEPTH]) -> Hash {
        let mut index = loan_id;
        let mut current = leaf;
        for (height, sibling) in siblings.iter().enumerate() {
            current = if index & 1 == 0 {
                branch::<H>(&self.domain, (height + 1) as u8, &current, sibling)
            } else {
                branch::<H>(&self.domain, (height + 1) as u8, sibling, &current)
            };
            index >>= 1;
        }
        current
    }
}

fn write_or_remove<S: NodeStore>(store: &mut S, key: NodeKey, value: Hash, empty: Hash) {
    if value == empty {
        store.remove(key);
    } else {
        store.set(key, value);
    }
}

fn branch<H: HashFunction>(domain: &Hash, height: u8, left: &Hash, right: &Hash) -> Hash {
    hash_parts::<H>(b"NCL/BOOK/NODE/v1", domain, &[&[height], left, right])
}

fn hash_parts<H: HashFunction>(tag: &[u8], domain: &Hash, parts: &[&[u8]]) -> Hash {
    let mut bytes =
        Vec::with_capacity(tag.len() + 32 + parts.iter().map(|part| part.len()).sum::<usize>());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(domain);
    for part in parts {
        bytes.extend_from_slice(part);
    }
    H::sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    struct Sha;
    impl HashFunction for Sha {
        fn sha256(bytes: &[u8]) -> Hash {
            Sha256::digest(bytes).into()
        }
    }
    #[derive(Clone, Default, PartialEq, Eq, Debug)]
    struct Memory(BTreeMap<NodeKey, Hash>);
    impl NodeStore for Memory {
        fn get(&self, key: NodeKey) -> Option<Hash> {
            self.0.get(&key).copied()
        }
        fn set(&mut self, key: NodeKey, value: Hash) {
            self.0.insert(key, value);
        }
        fn remove(&mut self, key: NodeKey) {
            self.0.remove(&key);
        }
    }

    #[test]
    fn updates_prove_complete_membership_and_reject_omission_or_other_deployments() {
        let book = Book::<Sha>::new([1; 32]);
        let mut store = Memory::default();
        let mut root = book.empty_root();
        let leaves = [1, 2, 50, u64::MAX].map(|id| (id, book.leaf_hash(id, &[id as u8; 32])));
        for (id, leaf) in leaves {
            root = book
                .update(&mut store, id, None, Some(leaf), &root)
                .unwrap();
        }
        for (id, leaf) in leaves {
            let proof = book.proof(&store, id);
            assert!(book.verify(id, Some(leaf), &proof, &root));
            assert!(!book.verify(id, None, &proof, &root));
            assert!(!Book::<Sha>::new([2; 32]).verify(id, Some(leaf), &proof, &root));
            let mut omitted = proof;
            omitted[0] = [0; 32];
            assert!(!book.verify(id, Some(leaf), &omitted, &root));
        }
        assert!(book.verify(99, None, &book.proof(&store, 99), &root));
        assert!(store.0.len() <= 4 * 65);
    }

    #[test]
    fn stale_updates_write_nothing_and_new_root_is_insertion_order_independent() {
        let book = Book::<Sha>::new([3; 32]);
        let mut left = Memory::default();
        let mut right = Memory::default();
        let leaf_a = book.leaf_hash(7, &[7; 32]);
        let leaf_b = book.leaf_hash(8, &[8; 32]);
        let root_a = book
            .update(&mut left, 7, None, Some(leaf_a), &book.empty_root())
            .unwrap();
        let snapshot = left.clone();
        assert_eq!(
            book.update(&mut left, 7, None, Some(leaf_b), &root_a),
            Err(Error::StaleLeaf)
        );
        assert_eq!(
            book.update(&mut left, 8, None, Some(leaf_b), &book.empty_root()),
            Err(Error::StaleRoot)
        );
        assert_eq!(left, snapshot);
        let final_left = book
            .update(&mut left, 8, None, Some(leaf_b), &root_a)
            .unwrap();
        let root_b = book
            .update(&mut right, 8, None, Some(leaf_b), &book.empty_root())
            .unwrap();
        let final_right = book
            .update(&mut right, 7, None, Some(leaf_a), &root_b)
            .unwrap();
        assert_eq!(final_left, final_right);
        assert_eq!(left, right);
        let root = book
            .update(&mut left, 7, Some(leaf_a), None, &final_left)
            .unwrap();
        let root = book
            .update(&mut left, 8, Some(leaf_b), None, &root)
            .unwrap();
        assert_eq!(root, book.empty_root());
        assert!(left.0.is_empty());
    }
}
