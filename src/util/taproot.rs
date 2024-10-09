// Rust Bitcoin Library
// Written in 2019 by
//     The rust-bitcoin developers.
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Bitcoin Taproot.
//!
//! This module provides support for taproot tagged hashes.
//!

use prelude::*;
use io;
use secp256k1::{self, Secp256k1};

use core::fmt;
use core::cmp::Reverse;
#[cfg(feature = "std")]
use std::error;

use hashes::{sha256, sha256t, Hash, HashEngine};
use schnorr::{TweakedPublicKey, UntweakedPublicKey, TapTweak};
use util::key::XOnlyPublicKey;
use Script;

use consensus::Encodable;

/// The SHA-256 midstate value for the TapLeaf hash.
const MIDSTATE_TAPLEAF: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];
// 9ce0e4e67c116c3938b3caf2c30f5089d3f3936c47636e607db33eeaddc6f0c9

/// The SHA-256 midstate value for the TapBranch hash.
const MIDSTATE_TAPBRANCH: [u8; 32] = [
    35, 168, 101, 169, 184, 164, 13, 167, 151, 124, 30, 4, 196, 158, 36, 111, 181, 190, 19, 118,
    157, 36, 201, 183, 181, 131, 181, 212, 168, 210, 38, 210,
];
// 23a865a9b8a40da7977c1e04c49e246fb5be13769d24c9b7b583b5d4a8d226d2

/// The SHA-256 midstate value for the TapTweak hash.
const MIDSTATE_TAPTWEAK: [u8; 32] = [
    209, 41, 162, 243, 112, 28, 101, 93, 101, 131, 182, 195, 185, 65, 151, 39, 149, 244, 226, 50,
    148, 253, 84, 244, 162, 174, 141, 133, 71, 202, 89, 11,
];
// d129a2f3701c655d6583b6c3b941972795f4e23294fd54f4a2ae8d8547ca590b

/// The SHA-256 midstate value for the [`TapSighashHash`].
const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    245, 4, 164, 37, 215, 248, 120, 59, 19, 99, 134, 138, 227, 229, 86, 88, 110, 238, 148, 93, 188,
    120, 136, 221, 2, 166, 226, 195, 24, 115, 254, 159,
];
// f504a425d7f8783b1363868ae3e556586eee945dbc7888dd02a6e2c31873fe9f

/// Internal macro to speficy the different taproot tagged hashes.
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr) => {
        sha256t_hash_newtype!($newtype, $tag, $midstate, $midstate_len, $docs, $reverse, stringify!($newtype));
    };

    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr, $sname:expr) => {
        #[doc = "The tag used for ["]
        #[doc = $sname]
        #[doc = "]"]
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $tag;

        impl sha256t::Tag for $tag {
            fn engine() -> sha256::HashEngine {
                let midstate = sha256::Midstate::from_inner($midstate);
                sha256::HashEngine::from_midstate(midstate, $midstate_len)
            }
        }

        hash_newtype!($newtype, sha256t::Hash<$tag>, 32, $docs, $reverse);
    };
}

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree leafs", false
);
sha256t_hash_newtype!(TapBranchHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree branches", false
);
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc="Taproot-tagged hash for public key tweaks", false
);
sha256t_hash_newtype!(TapSighashHash, TapSighashTag, MIDSTATE_TAPSIGHASH, 64,
    doc="Taproot-tagged hash for the taproot signature hash", false
);

impl TapTweakHash {
    /// Creates a new BIP341 [`TapTweakHash`] from key and tweak. Produces `H_taptweak(P||R)` where
    /// `P` is the internal key and `R` is the merkle root.
    pub fn from_key_and_tweak(
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> TapTweakHash {
        let mut eng = TapTweakHash::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(&h);
        } else {
            // nothing to hash
        }
        TapTweakHash::from_engine(eng)
    }
}

impl TapLeafHash {
    /// Computes the leaf hash from components.
    pub fn from_script(script: &Script, ver: LeafVersion) -> TapLeafHash {
        let mut eng = TapLeafHash::engine();
        ver.to_consensus()
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        script
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        TapLeafHash::from_engine(eng)
    }
}

impl TapBranchHash {
    /// Computes branch hash given two hashes of the nodes underneath it.
    pub fn from_node_hashes(a: sha256::Hash, b: sha256::Hash) -> TapBranchHash {
        let mut eng = TapBranchHash::engine();
        if a < b {
            eng.input(&a);
            eng.input(&b);
        } else {
            eng.input(&b);
            eng.input(&a);
        };
        TapBranchHash::from_engine(eng)
    }
}

/// Maximum depth of a taproot tree script spend path.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L229
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Size of a taproot control node.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L228
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Tapleaf mask for getting the leaf version from first byte of control block.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L225
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Tapscript leaf version.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L226
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Taproot annex prefix.
pub const TAPROOT_ANNEX_PREFIX: u8 = 0x50;
/// Tapscript control base size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L227
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Tapscript control max size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L230
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

// type alias for versioned tap script corresponding merkle proof
type ScriptMerkleProofMap = BTreeMap<(Script, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

/// Represents taproot spending information.
///
/// Taproot output corresponds to a combination of a single public key condition (known as the
/// internal key), and zero or more general conditions encoded in scripts organized in the form of a
/// binary tree.
///
/// Taproot can be spent by either:
/// - Spending using the key path i.e., with secret key corresponding to the tweaked `output_key`.
/// - By satisfying any of the scripts in the script spend path. Each script can be satisfied by
///   providing a witness stack consisting of the script's inputs, plus the script itself and the
///   control block.
///
/// If one or more of the spending conditions consist of just a single key (after aggregation), the
/// most likely key should be made the internal key.
/// See [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) for more details on
/// choosing internal keys for a taproot application.
///
/// Note: This library currently does not support
/// [annex](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaprootSpendInfo {
    /// The BIP341 internal key.
    internal_key: UntweakedPublicKey,
    /// The merkle root of the script tree (None if there are no scripts).
    merkle_root: Option<TapBranchHash>,
    /// The sign final output pubkey as per BIP 341.
    output_key_parity: secp256k1::Parity,
    /// The tweaked output key.
    output_key: TweakedPublicKey,
    /// Map from (script, leaf_version) to (sets of) [`TaprootMerkleBranch`]. More than one control
    /// block for a given script is only possible if it appears in multiple branches of the tree. In
    /// all cases, keeping one should be enough for spending funds, but we keep all of the paths so
    /// that a full tree can be constructed again from spending data if required.
    script_map: ScriptMerkleProofMap,
}

impl TaprootSpendInfo {
    /// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
    /// weights of satisfaction for that script.
    ///
    /// See [`TaprootBuilder::with_huffman_tree`] for more detailed documentation.
    pub fn with_huffman_tree<C, I>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        script_weights: I,
    ) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item=(u32, Script)>,
        C: secp256k1::Verification,
    {
        TaprootBuilder::with_huffman_tree(script_weights)?.finalize(secp, internal_key)
    }

    /// Creates a new key spend with `internal_key` and `merkle_root`. Provide [`None`] for
    /// the `merkle_root` if there is no script path.
    ///
    /// *Note*: As per BIP341
    ///
    /// When the merkle root is [`None`], the output key commits to an unspendable script path
    /// instead of having no script path. This is achieved by computing the output key point as
    /// `Q = P + int(hashTapTweak(bytes(P)))G`. See also [`TaprootSpendInfo::tap_tweak`].
    ///
    /// Refer to BIP 341 footnote ('Why should the output key always have a taproot commitment, even
    /// if there is no script path?') for more details.
    pub fn new_key_spend<C: secp256k1::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> Self {
        let (output_key, parity) = internal_key.tap_tweak(secp, merkle_root);
        Self {
            internal_key: internal_key,
            merkle_root: merkle_root,
            output_key_parity: parity,
            output_key: output_key,
            script_map: BTreeMap::new(),
        }
    }

    /// Returns the `TapTweakHash` for this [`TaprootSpendInfo`] i.e., the tweak using `internal_key`
    /// and `merkle_root`.
    pub fn tap_tweak(&self) -> TapTweakHash {
        TapTweakHash::from_key_and_tweak(self.internal_key, self.merkle_root)
    }

    /// Returns the internal key for this [`TaprootSpendInfo`].
    pub fn internal_key(&self) -> UntweakedPublicKey {
        self.internal_key
    }

    /// Returns the merkle root for this [`TaprootSpendInfo`].
    pub fn merkle_root(&self) -> Option<TapBranchHash> {
        self.merkle_root
    }

    /// Returns the output key (the key used in script pubkey) for this [`TaprootSpendInfo`].
    pub fn output_key(&self) -> TweakedPublicKey {
        self.output_key
    }

    /// Returns the parity of the output key. See also [`TaprootSpendInfo::output_key`].
    pub fn output_key_parity(&self) -> secp256k1::Parity {
        self.output_key_parity
    }

    /// Computes the [`TaprootSpendInfo`] from `internal_key` and `node`.
    ///
    /// This is useful when you want to manually build a taproot tree without using
    /// [`TaprootBuilder`].
    pub fn from_node_info<C: secp256k1::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        node: NodeInfo,
    ) -> TaprootSpendInfo {
        // Create as if it is a key spend path with the given merkle root
        let root_hash = Some(TapBranchHash::from_inner(node.hash.into_inner()));
        let mut info = TaprootSpendInfo::new_key_spend(secp, internal_key, root_hash);
        for leaves in node.leaves {
            let key = (leaves.script, leaves.ver);
            let value = leaves.merkle_branch;
            match info.script_map.get_mut(&key) {
                Some(set) => {
                    set.insert(value);
                    continue; // NLL fix
                }
                None => {}
            }
            let mut set = BTreeSet::new();
            set.insert(value);
            info.script_map.insert(key, set);
        }
        info
    }

    /// Returns the internal script map.
    pub fn as_script_map(&self) -> &ScriptMerkleProofMap {
        &self.script_map
    }

    /// Constructs a [`ControlBlock`] for particular script with the given version.
    ///
    /// # Returns
    ///
    /// - If there are multiple control blocks possible, returns the shortest one.
    /// - If the script is not contained in the [`TaprootSpendInfo`], returns `None`.
    pub fn control_block(&self, script_ver: &(Script, LeafVersion)) -> Option<ControlBlock> {
        let merkle_branch_set = self.script_map.get(script_ver)?;
        // Choose the smallest one amongst the multiple script maps
        let smallest = merkle_branch_set
            .iter()
            .min_by(|x, y| x.0.len().cmp(&y.0.len()))
            .expect("Invariant: Script map key must contain non-empty set value");
        Some(ControlBlock {
            internal_key: self.internal_key,
            output_key_parity: self.output_key_parity,
            leaf_version: script_ver.1,
            merkle_branch: smallest.clone(),
        })
    }
}

/// Builder for building taproot iteratively. Users can specify tap leaf or omitted/hidden branches
/// in a depth-first search (DFS) walk order to construct this tree.
///
/// See Wikipedia for more details on [DFS](https://en.wikipedia.org/wiki/Depth-first_search).
// Similar to Taproot Builder in bitcoin core.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaprootBuilder {
    // The following doc-comment is from bitcoin core, but modified for Rust. It describes the
    // current state of the builder for a given tree.
    //
    // For each level in the tree, one NodeInfo object may be present. Branch at index 0 is
    // information about the root; further values are for deeper subtrees being explored.
    //
    // During the construction of Taptree, for every right branch taken to reach the position we're
    // currently working on, there will be a `(Some(_))` entry in branch corresponding to the left
    // branch at that level.
    //
    // For example, imagine this tree:     - N0 -
    //                                    /      \
    //                                   N1      N2
    //                                  /  \    /  \
    //                                 A    B  C   N3
    //                                            /  \
    //                                           D    E
    //
    // Initially, branch is empty. After processing leaf A, it would become {None, None, A}. When
    // processing leaf B, an entry at level 2 already exists, and it would thus be combined with it
    // to produce a level 1 entry, resulting in {None, N1}. Adding C and D takes us to {None, N1, C}
    // and {None, N1, C, D} respectively. When E is processed, it is combined with D, and then C,
    // and then N1, to produce the root, resulting in {N0}.
    //
    // This structure allows processing with just O(log n) overhead if the leaves are computed on
    // the fly.
    //
    // As an invariant, there can never be None entries at the end. There can also not be more than
    // 128 entries (as that would mean more than 128 levels in the tree). The depth of newly added
    // entries will always be at least equal to the current size of branch (otherwise it does not
    // correspond to a depth-first traversal of a tree). A branch is only empty if no entries have
    // ever be processed. A branch having length 1 corresponds to being done.
    branch: Vec<Option<NodeInfo>>,
}

impl TaprootBuilder {
    /// Creates a new instance of [`TaprootBuilder`].
    pub fn new() -> Self {
        TaprootBuilder { branch: vec![] }
    }

    /// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
    /// weights of satisfaction for that script.
    ///
    /// The weights represent the probability of each branch being taken. If probabilities/weights
    /// for each condition are known, constructing the tree as a Huffman Tree is the optimal way to
    /// minimize average case satisfaction cost. This function takes as input an iterator of
    /// `tuple(u32, &Script)` where `u32` represents the satisfaction weights of the branch. For
    /// example, [(3, S1), (2, S2), (5, S3)] would construct a [`TapTree`] that has optimal
    /// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%.
    ///
    /// # Errors:
    ///
    /// - When the optimal Huffman Tree has a depth more than 128.
    /// - If the provided list of script weights is empty.
    ///
    /// # Edge Cases:
    ///
    /// If the script weight calculations overflow, a sub-optimal tree may be generated. This should
    /// not happen unless you are dealing with billions of branches with weights close to 2^32.
    ///
    /// [`TapTree`]: ::util::psbt::TapTree
    pub fn with_huffman_tree<I>(
        script_weights: I,
    ) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item=(u32, Script)>,
    {
        let mut node_weights = BinaryHeap::<(Reverse<u32>, NodeInfo)>::new();
        for (p, leaf) in script_weights {
            node_weights.push((Reverse(p), NodeInfo::new_leaf_with_ver(leaf, LeafVersion::TapScript)));
        }
        if node_weights.is_empty() {
            return Err(TaprootBuilderError::IncompleteTree);
        }
        while node_weights.len() > 1 {
            // Combine the last two elements and insert a new node
            let (p1, s1) = node_weights.pop().expect("len must be at least two");
            let (p2, s2) = node_weights.pop().expect("len must be at least two");
            // Insert the sum of first two in the tree as a new node
            // N.B.: p1 + p2 can not practically saturate as you would need to have 2**32 max u32s
            // from the input to overflow. However, saturating is a reasonable behavior here as
            // huffman tree construction would treat all such elements as "very likely".
            let p = Reverse(p1.0.saturating_add(p2.0));
            node_weights.push((p, NodeInfo::combine(s1, s2)?));
        }
        // Every iteration of the loop reduces the node_weights.len() by exactly 1
        // Therefore, the loop will eventually terminate with exactly 1 element
        debug_assert_eq!(node_weights.len(), 1);
        let node = node_weights.pop().expect("huffman tree algorithm is broken").1;
        Ok(TaprootBuilder{branch: vec![Some(node)]})
    }

    /// Adds a leaf script at `depth` to the builder with script version `ver`. Errors if the leaves
    /// are not provided in DFS walk order. The depth of the root node is 0.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: Script,
        ver: LeafVersion,
    ) -> Result<Self, TaprootBuilderError> {
        let leaf = NodeInfo::new_leaf_with_ver(script, ver);
        self.insert(leaf, depth)
    }

    /// Adds a leaf script at `depth` to the builder with default script version. Errors if the
    /// leaves are not provided in DFS walk order. The depth of the root node is 0.
    ///
    /// See [`TaprootBuilder::add_leaf_with_ver`] for adding a leaf with specific version.
    pub fn add_leaf(self, depth: u8, script: Script) -> Result<Self, TaprootBuilderError> {
        self.add_leaf_with_ver(depth, script, LeafVersion::TapScript)
    }

    /// Adds a hidden/omitted node at `depth` to the builder. Errors if the leaves are not provided
    /// in DFS walk order. The depth of the root node is 0.
    pub fn add_hidden_node(self, depth: u8, hash: sha256::Hash) -> Result<Self, TaprootBuilderError> {
        let node = NodeInfo::new_hidden_node(hash);
        self.insert(node, depth)
    }

    /// Checks if the builder has finalized building a tree.
    pub fn is_finalized(&self) -> bool {
        self.branch.len() == 1 && self.branch[0].is_some()
    }

    /// Checks if the builder has hidden nodes.
    pub fn has_hidden_nodes(&self) -> bool {
        for node in &self.branch {
            if let Some(node) = node {
                if node.has_hidden_nodes {
                    return true
                }
            }
        }
        false
    }

    /// Creates a [`TaprootSpendInfo`] with the given internal key.
    ///
    // TODO: in a future breaking API change, this no longer needs to return result
    pub fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
    ) -> Result<TaprootSpendInfo, TaprootBuilderError> {
        match self.branch.pop() {
            None => Ok(TaprootSpendInfo::new_key_spend(secp, internal_key, None)),
            Some(Some(node)) => {
                Ok(TaprootSpendInfo::from_node_info(secp, internal_key, node))
            }
            _ => Err(TaprootBuilderError::IncompleteTree),

        }
    }

    pub(crate) fn branch(&self) -> &[Option<NodeInfo>] {
        &self.branch
    }

    /// Inserts a leaf at `depth`.
    fn insert(mut self, mut node: NodeInfo, mut depth: u8) -> Result<Self, TaprootBuilderError> {
        // early error on invalid depth. Though this will be checked later
        // while constructing TaprootMerkelBranch
        if depth as usize > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(TaprootBuilderError::InvalidMerkleTreeDepth(depth as usize));
        }
        // We cannot insert a leaf at a lower depth while a deeper branch is unfinished. Doing
        // so would mean the add_leaf/add_hidden invocations do not correspond to a DFS traversal of a
        // binary tree.
        if depth as usize + 1 < self.branch.len() {
            return Err(TaprootBuilderError::NodeNotInDfsOrder);
        }

        while self.branch.len() == depth as usize + 1 {
            let child = match self.branch.pop() {
                None => unreachable!("Len of branch checked to be >= 1"),
                Some(Some(child)) => child,
                // Needs an explicit push to add the None that we just popped.
                // Cannot use .last() because of borrow checker issues.
                Some(None) => {
                    self.branch.push(None);
                    break;
                } // Cannot combine further
            };
            if depth == 0 {
                // We are trying to combine two nodes at root level.
                // Can't propagate further up than the root
                return Err(TaprootBuilderError::OverCompleteTree);
            }
            node = NodeInfo::combine(node, child)?;
            // Propagate to combine nodes at a lower depth
            depth -= 1;
        }

        if self.branch.len() < depth as usize + 1 {
            // add enough nodes so that we can insert node at depth `depth`
            let num_extra_nodes = depth as usize + 1 - self.branch.len();
            self.branch
                .extend((0..num_extra_nodes).into_iter().map(|_| None));
        }
        // Push the last node to the branch
        self.branch[depth as usize] = Some(node);
        Ok(self)
    }
}

/// Represents the node information in taproot tree.
///
/// Helper type used in merkle tree construction allowing one to build sparse merkle trees. The node
/// represents part of the tree that has information about all of its descendants.
/// See how [`TaprootBuilder`] works for more details.
///
/// You can use [`TaprootSpendInfo::from_node_info`] to a get a [`TaprootSpendInfo`] from the merkle
/// root [`NodeInfo`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeInfo {
    /// Merkle hash for this node.
    pub(crate) hash: sha256::Hash,
    /// Information about leaves inside this node.
    pub(crate) leaves: Vec<ScriptLeaf>,
    /// Tracks information on hidden nodes below this node.
    pub(crate) has_hidden_nodes: bool,
}

impl NodeInfo {
    /// Creates a new [`NodeInfo`] with omitted/hidden info.
    pub fn new_hidden_node(hash: sha256::Hash) -> Self {
        Self {
            hash: hash,
            leaves: vec![],
            has_hidden_nodes: true
        }
    }

    /// Creates a new leaf [`NodeInfo`] with given [`Script`] and [`LeafVersion`].
    pub fn new_leaf_with_ver(script: Script, ver: LeafVersion) -> Self {
        let leaf = ScriptLeaf::new(script, ver);
        Self {
            hash: sha256::Hash::from_inner(leaf.leaf_hash().into_inner()),
            leaves: vec![leaf],
            has_hidden_nodes: false,
        }
    }

    /// Combines two [`NodeInfo`] to create a new parent.
    pub fn combine(a: Self, b: Self) -> Result<Self, TaprootBuilderError> {
        let mut all_leaves = Vec::with_capacity(a.leaves.len() + b.leaves.len());
        for mut a_leaf in a.leaves {
            a_leaf.merkle_branch.push(b.hash)?; // add hashing partner
            all_leaves.push(a_leaf);
        }
        for mut b_leaf in b.leaves {
            b_leaf.merkle_branch.push(a.hash)?; // add hashing partner
            all_leaves.push(b_leaf);
        }
        let hash = TapBranchHash::from_node_hashes(a.hash, b.hash);
        Ok(Self {
            hash: sha256::Hash::from_inner(hash.into_inner()),
            leaves: all_leaves,
            has_hidden_nodes: a.has_hidden_nodes || b.has_hidden_nodes
        })
    }
}

/// Store information about taproot leaf node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScriptLeaf {
    /// The underlying script.
    script: Script,
    /// The leaf version.
    ver: LeafVersion,
    /// The merkle proof (hashing partners) to get this node.
    merkle_branch: TaprootMerkleBranch,
}

impl ScriptLeaf {
    /// Creates an new [`ScriptLeaf`] from `script` and `ver` and no merkle branch.
    fn new(script: Script, ver: LeafVersion) -> Self {
        Self {
            script: script,
            ver: ver,
            merkle_branch: TaprootMerkleBranch(vec![]),
        }
    }

    /// Returns the depth of this script leaf in the tap tree.
    #[inline]
    pub fn depth(&self) -> u8 {
        // The depth is guaranteed to be < 127 by the TaprootBuilder type.
        // TODO: Following MSRV bump implement via `try_into().expect("")`.
        self.merkle_branch.0.len() as u8
    }

    /// Computes a leaf hash for this [`ScriptLeaf`].
    #[inline]
    pub fn leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.script, self.ver)
    }

    /// Returns reference to the leaf script.
    #[inline]
    pub fn script(&self) -> &Script {
        &self.script
    }

    /// Returns leaf version of the script.
    #[inline]
    pub fn leaf_version(&self) -> LeafVersion {
        self.ver
    }

    /// Returns reference to the merkle proof (hashing partners) to get this
    /// node in form of [`TaprootMerkleBranch`].
    #[inline]
    pub fn merkle_branch(&self) -> &TaprootMerkleBranch {
        &self.merkle_branch
    }
}

/// The merkle proof for inclusion of a tree in a taptree hash.
// The type of hash is `sha256::Hash` because the vector might contain both `TapBranchHash` and
// `TapLeafHash`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaprootMerkleBranch(Vec<sha256::Hash>);

impl TaprootMerkleBranch {
    /// Returns a reference to the inner vector of hashes.
    pub fn as_inner(&self) -> &[sha256::Hash] {
        &self.0
    }

    /// Creates a merkle proof from raw data representing a list of hashes.
    pub fn from_slice(sl: &[u8]) -> Result<Self, TaprootError> {
        if sl.len() % TAPROOT_CONTROL_NODE_SIZE != 0 {
            Err(TaprootError::InvalidMerkleBranchSize(sl.len()))
        } else if sl.len() > TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(sl.len() / TAPROOT_CONTROL_NODE_SIZE))
        } else {
            let inner = sl
                // TODO: Use chunks_exact after MSRV changes to 1.31
                .chunks(TAPROOT_CONTROL_NODE_SIZE)
                .map(|chunk| {
                    sha256::Hash::from_slice(chunk)
                        .expect("chunk exact always returns the correct size")
                })
                .collect();
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        for hash in self.0.iter() {
            writer.write_all(hash)?;
        }
        Ok(self.0.len() * sha256::Hash::LEN)
    }

    /// Serializes `self` as bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.0.iter().map(|e| e.as_inner()).flatten().map(|x| *x).collect::<Vec<u8>>()
    }

    /// Appends elements to proof.
    fn push(&mut self, h: sha256::Hash) -> Result<(), TaprootBuilderError> {
        if self.0.len() >= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootBuilderError::InvalidMerkleTreeDepth(self.0.len()))
        } else {
            self.0.push(h);
            Ok(())
        }
    }

    /// Creates a merkle proof from list of hashes.
    ///
    /// # Errors
    ///
    /// If inner proof length is more than [`TAPROOT_CONTROL_MAX_NODE_COUNT`] (128).
    pub fn from_inner(inner: Vec<sha256::Hash>) -> Result<Self, TaprootError> {
        if inner.len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(inner.len()))
        } else {
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Returns the inner list of hashes.
    pub fn into_inner(self) -> Vec<sha256::Hash> {
        self.0
    }
}

/// Control block data structure used in Tapscript satisfaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlBlock {
    /// The tapleaf version.
    pub leaf_version: LeafVersion,
    /// The parity of the output key (NOT THE INTERNAL KEY WHICH IS ALWAYS XONLY).
    pub output_key_parity: secp256k1::Parity,
    /// The internal key.
    pub internal_key: UntweakedPublicKey,
    /// The merkle proof of a script associated with this leaf.
    pub merkle_branch: TaprootMerkleBranch,
}

impl ControlBlock {
    /// Constructs a `ControlBlock` from slice. This is an extra witness element that provides the
    /// proof that taproot script pubkey is correctly computed with some specified leaf hash. This
    /// is the last element in taproot witness when spending a output via script path.
    ///
    /// # Errors
    ///
    /// - [`TaprootError::InvalidControlBlockSize`] if `sl` is not of size 1 + 32 + 32N for any N >= 0.
    /// - [`TaprootError::InvalidParity`] if first byte of `sl` is not a valid output key parity.
    /// - [`TaprootError::InvalidTaprootLeafVersion`] if first byte of `sl` is not a valid leaf version.
    /// - [`TaprootError::InvalidInternalKey`] if internal key is invalid (first 32 bytes after the parity byte).
    /// - [`TaprootError::InvalidMerkleTreeDepth`] if merkle tree is too deep (more than 128 levels).
    pub fn from_slice(sl: &[u8]) -> Result<ControlBlock, TaprootError> {
        if sl.len() < TAPROOT_CONTROL_BASE_SIZE
            || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(TaprootError::InvalidControlBlockSize(sl.len()));
        }
        let output_key_parity = secp256k1::Parity::from_i32((sl[0] & 1) as i32)
            .map_err(TaprootError::InvalidParity)?;
        let leaf_version = LeafVersion::from_consensus(sl[0] & TAPROOT_LEAF_MASK)?;
        let internal_key = UntweakedPublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
            .map_err(TaprootError::InvalidInternalKey)?;
        let merkle_branch = TaprootMerkleBranch::from_slice(&sl[TAPROOT_CONTROL_BASE_SIZE..])?;
        Ok(ControlBlock {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_branch,
        })
    }

    /// Returns the size of control block. Faster and more efficient than calling
    /// `Self::serialize().len()`. Can be handy for fee estimation.
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.as_inner().len()
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let first_byte: u8 = i32::from(self.output_key_parity) as u8 | self.leaf_version.to_consensus();
        writer.write_all(&[first_byte])?;
        writer.write_all(&self.internal_key.serialize())?;
        self.merkle_branch.encode(&mut writer)?;
        Ok(self.size())
    }

    /// Serializes the control block.
    ///
    /// This would be required when using [`ControlBlock`] as a witness element while spending an
    /// output via script path. This serialization does not include the [`::VarInt`] prefix that would
    /// be applied when encoding this element as a witness.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf).expect("writers don't error");
        buf
    }

    /// Verifies that a control block is correct proof for a given output key and script.
    ///
    /// Only checks that script is contained inside the taptree described by output key. Full
    /// verification must also execute the script with witness data.
    pub fn verify_taproot_commitment<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_key: XOnlyPublicKey,
        script: &Script,
    ) -> bool {
        // compute the script hash
        // Initially the curr_hash is the leaf hash
        let leaf_hash = TapLeafHash::from_script(&script, self.leaf_version);
        let mut curr_hash = TapBranchHash::from_inner(leaf_hash.into_inner());
        // Verify the proof
        for elem in self.merkle_branch.as_inner() {
            // Recalculate the curr hash as parent hash
            curr_hash = TapBranchHash::from_node_hashes(
                sha256::Hash::from_inner(curr_hash.into_inner()),
                *elem
            );
        }
        // compute the taptweak
        let tweak = TapTweakHash::from_key_and_tweak(self.internal_key, Some(curr_hash));
        self.internal_key.tweak_add_check(
            secp,
            &output_key,
            self.output_key_parity,
            tweak.into_inner(),
        )
    }
}

/// Inner type representing future (non-tapscript) leaf versions. See [`LeafVersion::Future`].
///
/// NB: NO PUBLIC CONSTRUCTOR!
/// The only way to construct this is by converting `u8` to [`LeafVersion`] and then extracting it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FutureLeafVersion(u8);

impl FutureLeafVersion {
    pub(self) fn from_consensus(version: u8) -> Result<FutureLeafVersion, TaprootError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => unreachable!("FutureLeafVersion::from_consensus should be never called for 0xC0 value"),
            TAPROOT_ANNEX_PREFIX => Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(TaprootError::InvalidTaprootLeafVersion(odd)),
            even => Ok(FutureLeafVersion(even))
        }
    }

    /// Returns the consensus representation of this [`FutureLeafVersion`].
    #[inline]
    pub fn to_consensus(self) -> u8 {
        self.0
    }
}

impl fmt::Display for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// The leaf version for tapleafs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafVersion {
    /// BIP-342 tapscript.
    TapScript,

    /// Future leaf version.
    Future(FutureLeafVersion)
}

impl LeafVersion {
    /// Creates a [`LeafVersion`] from consensus byte representation.
    ///
    /// # Errors
    ///
    /// - If the last bit of the `version` is odd.
    /// - If the `version` is 0x50 ([`TAPROOT_ANNEX_PREFIX`]).
    pub fn from_consensus(version: u8) -> Result<Self, TaprootError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(LeafVersion::TapScript),
            TAPROOT_ANNEX_PREFIX => Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
            future => FutureLeafVersion::from_consensus(future).map(LeafVersion::Future),
        }
    }

    /// Returns the consensus representation of this [`LeafVersion`].
    pub fn to_consensus(self) -> u8 {
        match self {
            LeafVersion::TapScript => TAPROOT_LEAF_TAPSCRIPT,
            LeafVersion::Future(version) => version.to_consensus(),
        }
    }
}

impl fmt::Display for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, f.alternate()) {
            (LeafVersion::TapScript, true) => f.write_str("tapscript"),
            (LeafVersion::TapScript, false) => fmt::Display::fmt(&TAPROOT_LEAF_TAPSCRIPT, f),
            (LeafVersion::Future(version), true) => write!(f, "future_script_{:#02x}", version.0),
            (LeafVersion::Future(version), false) => fmt::Display::fmt(version, f),
        }
    }
}

impl fmt::LowerHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_consensus(), f)
    }
}

impl fmt::UpperHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.to_consensus(), f)
    }
}

/// Serializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for LeafVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        serializer.serialize_u8(self.to_consensus())
    }
}

/// Deserializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for LeafVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>
    {
        struct U8Visitor;
        impl<'de> ::serde::de::Visitor<'de> for U8Visitor {
            type Value = LeafVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid consensus-encoded taproot leaf version")
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
            {
                LeafVersion::from_consensus(value).map_err(|_| {
                    E::invalid_value(::serde::de::Unexpected::Unsigned(value as u64), &"consensus-encoded leaf version as u8")
                })
            }
        }

        deserializer.deserialize_u8(U8Visitor)
    }
}

/// Detailed error type for taproot builder.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootBuilderError {
    /// Merkle tree depth must not be more than 128.
    InvalidMerkleTreeDepth(usize),
    /// Nodes must be added specified in DFS walk order.
    NodeNotInDfsOrder,
    /// Two nodes at depth 0 are not allowed.
    OverCompleteTree,
    /// Invalid taproot internal key.
    InvalidInternalKey(secp256k1::Error),
    /// Called finalize on an incomplete tree.
    IncompleteTree,
    /// Called finalize on a empty tree.
    EmptyTree,
}

impl fmt::Display for TaprootBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootBuilderError::NodeNotInDfsOrder => {
                write!(f, "add_leaf/add_hidden must be called in DFS walk order",)
            }
            TaprootBuilderError::OverCompleteTree => write!(
                f,
                "Attempted to create a tree with two nodes at depth 0. There must\
                only be a exactly one node at depth 0",
            ),
            TaprootBuilderError::InvalidMerkleTreeDepth(d) => {
                write!(f, "Merkle Tree depth({}) must be less than {}", d, TAPROOT_CONTROL_MAX_NODE_COUNT)
            }
            TaprootBuilderError::InvalidInternalKey(e) => {
                write!(f, "Invalid Internal XOnly key : {}", e)
            }
            TaprootBuilderError::IncompleteTree => {
                write!(f, "Called finalize on an incomplete tree")
            }
            TaprootBuilderError::EmptyTree => {
                write!(f, "Called finalize on an empty tree")
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for TaprootBuilderError {}

/// Detailed error type for taproot utilities.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootError {
    /// Proof size must be a multiple of 32.
    InvalidMerkleBranchSize(usize),
    /// Merkle tree depth must not be more than 128.
    InvalidMerkleTreeDepth(usize),
    /// The last bit of tapleaf version must be zero.
    InvalidTaprootLeafVersion(u8),
    /// Invalid control block size.
    InvalidControlBlockSize(usize),
    /// Invalid taproot internal key.
    InvalidInternalKey(secp256k1::Error),
    /// Invalid parity for internal key.
    InvalidParity(secp256k1::InvalidParityValue),
    /// Empty tap tree.
    EmptyTree,
}

impl fmt::Display for TaprootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootError::InvalidMerkleBranchSize(sz) => write!(
                f,
                "Merkle branch size({}) must be a multiple of {}",
                sz, TAPROOT_CONTROL_NODE_SIZE
            ),
            TaprootError::InvalidMerkleTreeDepth(d) => write!(
                f,
                "Merkle Tree depth({}) must be less than {}",
                d, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootError::InvalidTaprootLeafVersion(v) => write!(
                f,
                "Leaf version({}) must have the least significant bit 0",
                v
            ),
            TaprootError::InvalidControlBlockSize(sz) => write!(
                f,
                "Control Block size({}) must be of the form 33 + 32*m where  0 <= m <= {} ",
                sz, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            // TODO: add source when in MSRV
            TaprootError::InvalidInternalKey(e) => write!(f, "Invalid Internal XOnly key : {}", e),
            TaprootError::InvalidParity(e) => write!(f, "Invalid parity value for internal key: {}", e),
            TaprootError::EmptyTree => write!(f, "Taproot Tree must contain at least one script"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for TaprootError {}
