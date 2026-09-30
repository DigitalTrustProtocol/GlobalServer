//! `dtp-store`: the durable event store (ingest-storage.md § Event store).
//!
//! Keeps only slot winners with their signatures (enough to re-serve and
//! re-verify), slot floors from NIP-09 deletions, tombstones for deleted ids
//! not seen yet, and an ingest log for replay. The graph is rebuilt from it at
//! start-up. The engine is RocksDB (decision GS-D1); every batch is one
//! synced atomic `WriteBatch`.
//!
//! Column families (`kind` is big-endian `u32`, ids and pubkeys are raw 32
//! bytes):
//!
//! | Column family | Key | Value |
//! | --- | --- | --- |
//! | `slots` | `kind ‖ author ‖ d` | JSON `{ event?, floor?, seq }` (kind 10011 slots are the replaceable winners) |
//! | `by_id` | event id | slot key |
//! | `by_author` | `author ‖ slot key` | empty |
//! | `log` | `seq` (`u64` BE) | slot key |
//! | `tombstones` | event id | deleter pubkey |
//! | `meta` | UTF-8 name | bytes |

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Direction, IteratorMode, Options,
    WriteBatch, WriteOptions,
};
use serde::{Deserialize, Serialize};

use dtp_model::Event;

const SLOTS: &str = "slots";
const BY_ID: &str = "by_id";
const BY_AUTHOR: &str = "by_author";
const LOG: &str = "log";
const TOMBSTONES: &str = "tombstones";
const META: &str = "meta";
const FAMILIES: [&str; 6] = [SLOTS, BY_ID, BY_AUTHOR, LOG, TOMBSTONES, META];

pub const SCHEMA_VERSION: &str = "dtp-global-store/1";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("corrupt record: {0}")]
    Corrupt(String),
}

impl From<rocksdb::Error> for StoreError {
    fn from(e: rocksdb::Error) -> Self {
        StoreError::Storage(e.into_string())
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Slot address `(kind, author, d)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SlotAddr {
    pub kind: u32,
    pub pubkey: String,
    pub d: String,
}

impl SlotAddr {
    pub fn key(&self) -> Result<Vec<u8>> {
        let author = dtp_model::hex32(&self.pubkey)
            .ok_or_else(|| StoreError::Corrupt(format!("pubkey {}", self.pubkey)))?;
        let mut key = Vec::with_capacity(36 + self.d.len());
        key.extend_from_slice(&self.kind.to_be_bytes());
        key.extend_from_slice(&author);
        key.extend_from_slice(self.d.as_bytes());
        Ok(key)
    }

    pub fn from_key(key: &[u8]) -> Result<SlotAddr> {
        if key.len() < 36 {
            return Err(StoreError::Corrupt("short slot key".into()));
        }
        let kind = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
        let pubkey = hex::encode(&key[4..36]);
        let d = String::from_utf8(key[36..].to_vec())
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(SlotAddr { kind, pubkey, d })
    }
}

/// Stored slot state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
    #[serde(default)]
    pub seq: u64,
}

/// One change in a write batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOp {
    /// Sets the slot's winner (`None`: no winner) and floor.
    PutSlot {
        addr: SlotAddr,
        event: Option<Event>,
        floor: Option<u64>,
    },
    /// Sets a slot's floor, keeping its winner.
    SetFloor { addr: SlotAddr, floor: u64 },
    /// Records a deletion of an id the store does not hold.
    Tombstone { id: String, deleter: String },
    /// Clears a tombstone (the deleted event arrived and was refused).
    ClearTombstone { id: String },
    /// Sets a meta value.
    Meta { name: String, value: Vec<u8> },
}

/// What replay hands back at start-up.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Slot winners in ingest order.
    pub winners: Vec<Event>,
    /// Slots with a floor: `(address, floor)`.
    pub floors: Vec<(SlotAddr, u64)>,
    /// `(deleted id, deleter)`.
    pub tombstones: Vec<(String, String)>,
}

/// The event store contract.
pub trait EventStore: Send + Sync {
    /// Applies a batch atomically.
    fn write(&self, ops: &[WriteOp]) -> Result<()>;
    /// A stored winner by id.
    fn event_by_id(&self, id: &str) -> Result<Option<Event>>;
    /// Winners by author, optionally filtered by kind, newest first.
    fn events_by_author(&self, author: &str, kinds: &[u32], limit: usize) -> Result<Vec<Event>>;
    /// Everything needed to rebuild the graph.
    fn snapshot(&self) -> Result<Snapshot>;
    fn meta(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Number of stored winners.
    fn winner_count(&self) -> Result<u64>;
}

/// RocksDB-backed store. `path` is a directory.
pub struct RocksDbStore {
    db: DB,
    /// Serializes batches: a batch reads slots and the sequence counter
    /// before it writes them.
    writer: Mutex<()>,
    /// Entries in `log` (RocksDB has no exact key count).
    winners: AtomicU64,
}

impl RocksDbStore {
    pub fn open(path: &Path) -> Result<RocksDbStore> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(DBCompressionType::Lz4);
        let families = FAMILIES.map(|name| {
            let mut cf = Options::default();
            cf.set_compression_type(DBCompressionType::Lz4);
            ColumnFamilyDescriptor::new(name, cf)
        });
        let db = DB::open_cf_descriptors(&opts, path, families)?;
        let meta = cf(&db, META)?;
        if db.get_cf(meta, "schema")?.is_none() {
            db.put_cf(meta, "schema", SCHEMA_VERSION)?;
        }
        let mut winners = 0;
        for item in db.iterator_cf(cf(&db, LOG)?, IteratorMode::Start) {
            item?;
            winners += 1;
        }
        Ok(RocksDbStore {
            db,
            writer: Mutex::new(()),
            winners: AtomicU64::new(winners),
        })
    }
}

fn cf<'a>(db: &'a DB, name: &str) -> Result<&'a ColumnFamily> {
    db.cf_handle(name)
        .ok_or_else(|| StoreError::Storage(format!("missing column family {name}")))
}

fn decode_slot(bytes: &[u8]) -> Result<SlotValue> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn encode_slot(value: &SlotValue) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| StoreError::Corrupt(e.to_string()))
}

/// One batch under construction: reads see its own pending writes.
struct Batch<'a> {
    db: &'a DB,
    batch: WriteBatch,
    pending: HashMap<(&'static str, Vec<u8>), Option<Vec<u8>>>,
    winners: i64,
}

impl<'a> Batch<'a> {
    fn get(&self, family: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.pending.get(&(family, key.to_vec())) {
            Some(value) => Ok(value.clone()),
            None => Ok(self.db.get_cf(cf(self.db, family)?, key)?),
        }
    }

    fn put(&mut self, family: &'static str, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.put_cf(cf(self.db, family)?, key, value);
        self.pending
            .insert((family, key.to_vec()), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, family: &'static str, key: &[u8]) -> Result<()> {
        self.batch.delete_cf(cf(self.db, family)?, key);
        self.pending.insert((family, key.to_vec()), None);
        Ok(())
    }

    fn slot(&self, key: &[u8]) -> Result<Option<SlotValue>> {
        self.get(SLOTS, key)?.map(|v| decode_slot(&v)).transpose()
    }

    fn next_seq(&mut self) -> Result<u64> {
        let current = self
            .get(META, b"seq")?
            .map(|b| {
                let mut a = [0u8; 8];
                let n = 8.min(b.len());
                a[..n].copy_from_slice(&b[..n]);
                u64::from_be_bytes(a)
            })
            .unwrap_or(0);
        let next = current + 1;
        self.put(META, b"seq", &next.to_be_bytes())?;
        Ok(next)
    }

    fn apply(&mut self, op: &WriteOp) -> Result<()> {
        match op {
            WriteOp::PutSlot { addr, event, floor } => {
                let key = addr.key()?;
                if let Some(old) = self.slot(&key)? {
                    if let Some(old_event) = &old.event
                        && let Some(id) = dtp_model::hex32(&old_event.id)
                    {
                        self.delete(BY_ID, &id)?;
                    }
                    if old.seq > 0 {
                        self.delete(LOG, &old.seq.to_be_bytes())?;
                        self.winners -= 1;
                    }
                }
                let mut author_key = key[4..36].to_vec();
                author_key.extend_from_slice(&key);
                if event.is_none() && floor.is_none() {
                    self.delete(SLOTS, &key)?;
                    return self.delete(BY_AUTHOR, &author_key);
                }
                let seq = if event.is_some() { self.next_seq()? } else { 0 };
                let value = SlotValue {
                    event: event.clone(),
                    floor: *floor,
                    seq,
                };
                self.put(SLOTS, &key, &encode_slot(&value)?)?;
                if let Some(ev) = event {
                    let id = dtp_model::hex32(&ev.id)
                        .ok_or_else(|| StoreError::Corrupt("event id".into()))?;
                    self.put(BY_ID, &id, &key)?;
                    self.put(BY_AUTHOR, &author_key, &[])?;
                    self.put(LOG, &seq.to_be_bytes(), &key)?;
                    self.winners += 1;
                } else {
                    self.delete(BY_AUTHOR, &author_key)?;
                }
            }
            WriteOp::SetFloor { addr, floor } => {
                let key = addr.key()?;
                let mut value = self.slot(&key)?.unwrap_or_default();
                value.floor = Some(value.floor.map_or(*floor, |f| f.max(*floor)));
                self.put(SLOTS, &key, &encode_slot(&value)?)?;
            }
            WriteOp::Tombstone { id, deleter } => {
                let id = dtp_model::hex32(id)
                    .ok_or_else(|| StoreError::Corrupt("tombstone id".into()))?;
                let deleter = dtp_model::hex32(deleter)
                    .ok_or_else(|| StoreError::Corrupt("deleter".into()))?;
                self.put(TOMBSTONES, &id, &deleter)?;
            }
            WriteOp::ClearTombstone { id } => {
                if let Some(id) = dtp_model::hex32(id) {
                    self.delete(TOMBSTONES, &id)?;
                }
            }
            WriteOp::Meta { name, value } => self.put(META, name.as_bytes(), value)?,
        }
        Ok(())
    }
}

impl EventStore for RocksDbStore {
    fn write(&self, ops: &[WriteOp]) -> Result<()> {
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StoreError::Storage("writer lock poisoned".into()))?;
        let mut batch = Batch {
            db: &self.db,
            batch: WriteBatch::default(),
            pending: HashMap::new(),
            winners: 0,
        };
        for op in ops {
            batch.apply(op)?;
        }
        let mut sync = WriteOptions::default();
        sync.set_sync(true);
        self.db.write_opt(batch.batch, &sync)?;
        let count = self.winners.load(Ordering::Relaxed);
        self.winners.store(
            count.saturating_add_signed(batch.winners),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn event_by_id(&self, id: &str) -> Result<Option<Event>> {
        let Some(raw) = dtp_model::hex32(id) else {
            return Ok(None);
        };
        let snap = self.db.snapshot();
        let Some(key) = snap.get_cf(cf(&self.db, BY_ID)?, raw)? else {
            return Ok(None);
        };
        let Some(value) = snap.get_cf(cf(&self.db, SLOTS)?, key)? else {
            return Ok(None);
        };
        Ok(decode_slot(&value)?.event.filter(|e| e.id == id))
    }

    fn events_by_author(&self, author: &str, kinds: &[u32], limit: usize) -> Result<Vec<Event>> {
        let Some(raw) = dtp_model::hex32(author) else {
            return Ok(Vec::new());
        };
        let snap = self.db.snapshot();
        let slots = cf(&self.db, SLOTS)?;
        let mut out = Vec::new();
        let from = IteratorMode::From(&raw, Direction::Forward);
        for item in snap.iterator_cf(cf(&self.db, BY_AUTHOR)?, from) {
            let (k, _) = item?;
            if !k.starts_with(&raw) {
                break;
            }
            let key = &k[32..];
            if !kinds.is_empty() {
                let kind = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                if !kinds.contains(&kind) {
                    continue;
                }
            }
            if let Some(v) = snap.get_cf(slots, key)?
                && let Some(ev) = decode_slot(&v)?.event
            {
                out.push(ev);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        out.truncate(limit);
        Ok(out)
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let db = self.db.snapshot();
        let slots = cf(&self.db, SLOTS)?;
        let mut snap = Snapshot::default();
        for item in db.iterator_cf(cf(&self.db, LOG)?, IteratorMode::Start) {
            let (_, key) = item?;
            if let Some(v) = db.get_cf(slots, key)?
                && let Some(ev) = decode_slot(&v)?.event
            {
                snap.winners.push(ev);
            }
        }
        for item in db.iterator_cf(slots, IteratorMode::Start) {
            let (k, v) = item?;
            if let Some(floor) = decode_slot(&v)?.floor {
                snap.floors.push((SlotAddr::from_key(&k)?, floor));
            }
        }
        for item in db.iterator_cf(cf(&self.db, TOMBSTONES)?, IteratorMode::Start) {
            let (k, v) = item?;
            snap.tombstones.push((hex::encode(k), hex::encode(v)));
        }
        Ok(snap)
    }

    fn meta(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get_cf(cf(&self.db, META)?, name)?)
    }

    fn winner_count(&self) -> Result<u64> {
        Ok(self.winners.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtp_model::Keys;

    fn event(keys: &Keys, at: u64, kind: u32) -> Event {
        keys.sign_event(at, kind, vec![vec!["d".into(), "x".into()]], "")
    }

    #[test]
    fn put_replace_floor_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open(&dir.path().join("events")).unwrap();
        let alice = Keys::from_seed("alice");
        let addr = SlotAddr {
            kind: 32009,
            pubkey: alice.pubkey().into(),
            d: "ab".repeat(32),
        };
        let e1 = event(&alice, 10, 32009);
        let e2 = event(&alice, 20, 32009);
        store
            .write(&[WriteOp::PutSlot {
                addr: addr.clone(),
                event: Some(e1.clone()),
                floor: None,
            }])
            .unwrap();
        assert_eq!(store.event_by_id(&e1.id).unwrap(), Some(e1.clone()));
        store
            .write(&[WriteOp::PutSlot {
                addr: addr.clone(),
                event: Some(e2.clone()),
                floor: None,
            }])
            .unwrap();
        assert_eq!(store.event_by_id(&e1.id).unwrap(), None);
        assert_eq!(store.event_by_id(&e2.id).unwrap(), Some(e2.clone()));
        assert_eq!(
            store
                .events_by_author(alice.pubkey(), &[32009], 10)
                .unwrap(),
            vec![e2.clone()]
        );
        assert_eq!(
            store
                .events_by_author(alice.pubkey(), &[32014], 10)
                .unwrap(),
            vec![]
        );
        assert_eq!(store.winner_count().unwrap(), 1);

        // Deletion: winner removed, floor kept.
        store
            .write(&[
                WriteOp::PutSlot {
                    addr: addr.clone(),
                    event: None,
                    floor: Some(20),
                },
                WriteOp::Tombstone {
                    id: "cd".repeat(32),
                    deleter: alice.pubkey().into(),
                },
            ])
            .unwrap();
        assert_eq!(store.event_by_id(&e2.id).unwrap(), None);
        let snap = store.snapshot().unwrap();
        assert!(snap.winners.is_empty());
        assert_eq!(snap.floors, vec![(addr.clone(), 20)]);
        assert_eq!(snap.tombstones.len(), 1);

        // Reopen and replay order.
        let e3 = event(&alice, 30, 32009);
        let other = SlotAddr {
            d: "cd".repeat(32),
            ..addr.clone()
        };
        let e4 = event(&alice, 5, 32009);
        store
            .write(&[
                WriteOp::PutSlot {
                    addr: addr.clone(),
                    event: Some(e3.clone()),
                    floor: Some(20),
                },
                WriteOp::PutSlot {
                    addr: other,
                    event: Some(e4.clone()),
                    floor: None,
                },
                WriteOp::Meta {
                    name: "members".into(),
                    value: b"[]".to_vec(),
                },
            ])
            .unwrap();
        drop(store);
        let store = RocksDbStore::open(&dir.path().join("events")).unwrap();
        let snap = store.snapshot().unwrap();
        assert_eq!(snap.winners, vec![e3, e4]);
        assert_eq!(store.meta("members").unwrap(), Some(b"[]".to_vec()));
        assert_eq!(store.winner_count().unwrap(), 2);
        assert_eq!(
            store.meta("schema").unwrap(),
            Some(SCHEMA_VERSION.as_bytes().to_vec())
        );
    }

    #[test]
    fn one_batch_sees_its_own_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open(&dir.path().join("events")).unwrap();
        let alice = Keys::from_seed("alice");
        let addr = SlotAddr {
            kind: 32009,
            pubkey: alice.pubkey().into(),
            d: "ab".repeat(32),
        };
        let e1 = event(&alice, 10, 32009);
        let e2 = event(&alice, 20, 32009);
        store
            .write(&[
                WriteOp::PutSlot {
                    addr: addr.clone(),
                    event: Some(e1.clone()),
                    floor: None,
                },
                WriteOp::PutSlot {
                    addr: addr.clone(),
                    event: Some(e2.clone()),
                    floor: None,
                },
                WriteOp::SetFloor {
                    addr: addr.clone(),
                    floor: 15,
                },
                WriteOp::Tombstone {
                    id: "cd".repeat(32),
                    deleter: alice.pubkey().into(),
                },
                WriteOp::ClearTombstone {
                    id: "cd".repeat(32),
                },
            ])
            .unwrap();
        assert_eq!(store.event_by_id(&e1.id).unwrap(), None);
        assert_eq!(store.winner_count().unwrap(), 1);
        let snap = store.snapshot().unwrap();
        assert_eq!(snap.winners, vec![e2.clone()]);
        assert_eq!(snap.floors, vec![(addr, 15)]);
        assert!(snap.tombstones.is_empty());
        assert_eq!(
            store.meta("seq").unwrap(),
            Some(2u64.to_be_bytes().to_vec())
        );
        drop(store);
        let store = RocksDbStore::open(&dir.path().join("events")).unwrap();
        assert_eq!(store.winner_count().unwrap(), 1);
        assert_eq!(store.event_by_id(&e2.id).unwrap(), Some(e2));
    }
}
