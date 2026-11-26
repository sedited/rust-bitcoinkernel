//! Storable wrappers around the chainstate types that borrow a [`ChainstateManager`].

use std::{
    io::{self, ErrorKind::AlreadyExists},
    ops::Deref,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

use bitcoinkernel::{BlockHash, BlockTreeEntry, Chain, ChainstateManager, Context};

use crate::error::Error;

/// A chainstate manager together with the temporary directory backing it.
///
/// Derefs to the [`ChainstateManager`]; the directory is removed on drop.
/// Field order matters: the manager is dropped before the directory is removed.
pub struct TempChainstateManager {
    manager: ChainstateManager,
    _dir: TempDir,
}

impl TempChainstateManager {
    /// Creates a chainstate manager in a fresh temporary directory.
    pub fn new(context: &Context) -> Result<Self, Error> {
        // Same layout as the repo's tests: the tempdir is the data dir, with
        // `blocks` inside it.
        let dir = TempDir::create().map_err(|_| Error::Kernel)?;
        let blocks_dir = dir.0.join("blocks");
        // On failure `dir` is dropped here, removing the directory.
        let manager = ChainstateManager::new(
            context,
            &dir.0.to_string_lossy(),
            &blocks_dir.to_string_lossy(),
        )?;
        Ok(TempChainstateManager { manager, _dir: dir })
    }
}

impl Deref for TempChainstateManager {
    type Target = ChainstateManager;

    fn deref(&self) -> &ChainstateManager {
        &self.manager
    }
}

/// A uniquely named directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    /// Creates the directory. Names include the process ID and a counter, and
    /// existing directories (e.g. left by a killed earlier run) are never reused.
    fn create() -> io::Result<TempDir> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        loop {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("btck_conformance_test_{pid}_{n}"));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(TempDir(dir)),
                Err(e) if e.kind() == AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Handle to the active chain of a chainstate manager.
///
/// [`Chain`] borrows from its [`ChainstateManager`], so instead of storing the
/// borrow we keep the manager alive and fetch the active chain on each use. Like
/// the C API's chain view, it always reflects the current active chain.
pub struct ChainHandle {
    chainman: Rc<TempChainstateManager>,
}

impl ChainHandle {
    pub fn new(chainman: Rc<TempChainstateManager>) -> Self {
        ChainHandle { chainman }
    }

    pub fn chain(&self) -> Chain<'_> {
        self.chainman.active_chain()
    }

    pub fn chainman(&self) -> &Rc<TempChainstateManager> {
        &self.chainman
    }
}

/// Handle to an entry in a chainstate manager's block tree.
///
/// [`BlockTreeEntry`] borrows from its [`ChainstateManager`]. Entries in the block
/// index are stable and keyed by block hash, so the handle keeps the manager alive
/// and resolves the entry by hash on each use. After a reorg it still refers to
/// the same (now possibly stale) block.
pub struct BlockTreeEntryHandle {
    chainman: Rc<TempChainstateManager>,
    hash: BlockHash,
}

impl BlockTreeEntryHandle {
    pub fn new(chainman: Rc<TempChainstateManager>, entry: &BlockTreeEntry<'_>) -> Self {
        BlockTreeEntryHandle {
            chainman,
            hash: entry.block_hash().to_owned(),
        }
    }

    pub fn entry(&self) -> Result<BlockTreeEntry<'_>, Error> {
        self.chainman
            .get_block_tree_entry(&self.hash)
            .ok_or_else(|| Error::protocol("block tree entry no longer in block index"))
    }
}
