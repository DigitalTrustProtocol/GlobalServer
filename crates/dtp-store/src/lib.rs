//! `dtp-store`: the durable event store (ingest-storage.md § Event store).
//!
//! Keeps only slot winners with their signatures (enough to re-serve and
//! re-verify), slot floors from NIP-09 deletions, tombstones for deleted ids
//! not seen yet, and an ingest log for replay. The graph is rebuilt from it at
//! start-up. `redb` is the v1 engine (decision GS-D1 stays open; see PLAN.md).
//!
//! Tables (`kind` is big-endian `u32`, ids and pubkeys are raw 32 bytes):
//!
//! | Table | Key | Value |
//! | --- | --- | --- |
//! | `slots` | `kind ‖ author ‖ d` | JSON `{ event?, floor?, seq }` (kind 10011 slots are the replaceable winners) |
//! | `by_id` | event id | slot key |
//! | `by_author` | `author ‖ slot key` | empty |
//! | `log` | `seq` (`u64` BE) | slot key |
//! | `tombstones` | event id | deleter pubkey |
//! | `meta` | UTF-8 name | bytes |

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use dtp_model::Event;

const SLOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("slots");
const BY_ID: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_id");
const BY_AUTHOR: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_author");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
const TOMBSTONES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tombstones");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

pub const SCHEMA_VERSION: &str = "dtp-global-store/1";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("corrupt record: {0}")]
    Corrupt(String),
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                StoreError::Storage(e.to_string())
            }
        }
    )*};
}
from_redb!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

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

/// The event store contract (RocksDB can implement it later).
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

/// redb-backed store.
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    pub fn open(path: &Path) -> Result<RedbStore> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        {
            tx.open_table(SLOTS)?;
            tx.open_table(BY_ID)?;
            tx.open_table(BY_AUTHOR)?;
            tx.open_table(LOG)?;
            tx.open_table(TOMBSTONES)?;
            let mut meta = tx.open_table(META)?;
            if meta.get("schema")?.is_none() {
                meta.insert("schema", SCHEMA_VERSION.as_bytes())?;
            }
        }
        tx.commit()?;
        Ok(RedbStore { db })
    }

    fn next_seq(meta: &mut redb::Table<&str, &[u8]>) -> Result<u64> {
        let current = meta
            .get("seq")?
            .map(|v| {
                let b = v.value();
                let mut a = [0u8; 8];
                a.copy_from_slice(&b[..8.min(b.len())]);
                u64::from_be_bytes(a)
            })
            .unwrap_or(0);
        let next = current + 1;
        meta.insert("seq", next.to_be_bytes().as_slice())?;
        Ok(next)
    }
}

fn decode_slot(bytes: &[u8]) -> Result<SlotValue> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Corrupt(e.to_string()))
}

impl EventStore for RedbStore {
    fn write(&self, ops: &[WriteOp]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut slots = tx.open_table(SLOTS)?;
            let mut by_id = tx.open_table(BY_ID)?;
            let mut by_author = tx.open_table(BY_AUTHOR)?;
            let mut log = tx.open_table(LOG)?;
            let mut tombstones = tx.open_table(TOMBSTONES)?;
            let mut meta = tx.open_table(META)?;
            for op in ops {
                match op {
                    WriteOp::PutSlot { addr, event, floor } => {
                        let key = addr.key()?;
                        let old = slots
                            .get(key.as_slice())?
                            .map(|v| decode_slot(v.value()))
                            .transpose()?;
                        if let Some(old) = &old {
                            if let Some(old_event) = &old.event
                                && let Some(id) = dtp_model::hex32(&old_event.id)
                            {
                                by_id.remove(id.as_slice())?;
                            }
                            if old.seq > 0 {
                                log.remove(old.seq)?;
                            }
                        }
                        let mut author_key = key[4..36].to_vec();
                        author_key.extend_from_slice(&key);
                        if event.is_none() && floor.is_none() {
                            slots.remove(key.as_slice())?;
                            by_author.remove(author_key.as_slice())?;
                            continue;
                        }
                        let seq = if event.is_some() {
                            Self::next_seq(&mut meta)?
                        } else {
                            0
                        };
                        let value = SlotValue {
                            event: event.clone(),
                            floor: *floor,
                            seq,
                        };
                        let bytes = serde_json::to_vec(&value)
                            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
                        slots.insert(key.as_slice(), bytes.as_slice())?;
                        if let Some(ev) = event {
                            let id = dtp_model::hex32(&ev.id)
                                .ok_or_else(|| StoreError::Corrupt("event id".into()))?;
                            by_id.insert(id.as_slice(), key.as_slice())?;
                            by_author.insert(author_key.as_slice(), [].as_slice())?;
                            log.insert(seq, key.as_slice())?;
                        } else {
                            by_author.remove(author_key.as_slice())?;
                        }
                    }
                    WriteOp::SetFloor { addr, floor } => {
                        let key = addr.key()?;
                        let mut value = slots
                            .get(key.as_slice())?
                            .map(|v| decode_slot(v.value()))
                            .transpose()?
                            .unwrap_or_default();
                        value.floor = Some(value.floor.map_or(*floor, |f| f.max(*floor)));
                        let bytes = serde_json::to_vec(&value)
                            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
                        slots.insert(key.as_slice(), bytes.as_slice())?;
                    }
                    WriteOp::Tombstone { id, deleter } => {
                        let id = dtp_model::hex32(id)
                            .ok_or_else(|| StoreError::Corrupt("tombstone id".into()))?;
                        let deleter = dtp_model::hex32(deleter)
                            .ok_or_else(|| StoreError::Corrupt("deleter".into()))?;
                        tombstones.insert(id.as_slice(), deleter.as_slice())?;
                    }
                    WriteOp::ClearTombstone { id } => {
                        if let Some(id) = dtp_model::hex32(id) {
                            tombstones.remove(id.as_slice())?;
                        }
                    }
                    WriteOp::Meta { name, value } => {
                        meta.insert(name.as_str(), value.as_slice())?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn event_by_id(&self, id: &str) -> Result<Option<Event>> {
        let Some(raw) = dtp_model::hex32(id) else {
            return Ok(None);
        };
        let tx = self.db.begin_read()?;
        let by_id = tx.open_table(BY_ID)?;
        let Some(key) = by_id.get(raw.as_slice())? else {
            return Ok(None);
        };
        let slots = tx.open_table(SLOTS)?;
        let Some(value) = slots.get(key.value())? else {
            return Ok(None);
        };
        let slot = decode_slot(value.value())?;
        Ok(slot.event.filter(|e| e.id == id))
    }

    fn events_by_author(&self, author: &str, kinds: &[u32], limit: usize) -> Result<Vec<Event>> {
        let Some(raw) = dtp_model::hex32(author) else {
            return Ok(Vec::new());
        };
        let tx = self.db.begin_read()?;
        let by_author = tx.open_table(BY_AUTHOR)?;
        let slots = tx.open_table(SLOTS)?;
        let mut end = raw.to_vec();
        end.push(0xff);
        let mut out = Vec::new();
        for item in by_author.range(raw.as_slice()..end.as_slice())? {
            let (k, _) = item?;
            let key = &k.value()[32..];
            if !kinds.is_empty() {
                let kind = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                if !kinds.contains(&kind) {
                    continue;
                }
            }
            if let Some(v) = slots.get(key)?
                && let Some(ev) = decode_slot(v.value())?.event
            {
                out.push(ev);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        out.truncate(limit);
        Ok(out)
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let tx = self.db.begin_read()?;
        let slots = tx.open_table(SLOTS)?;
        let log = tx.open_table(LOG)?;
        let tombstones = tx.open_table(TOMBSTONES)?;
        let mut snap = Snapshot::default();
        for item in log.iter()? {
            let (_, key) = item?;
            if let Some(v) = slots.get(key.value())?
                && let Some(ev) = decode_slot(v.value())?.event
            {
                snap.winners.push(ev);
            }
        }
        for item in slots.iter()? {
            let (k, v) = item?;
            let slot = decode_slot(v.value())?;
            if let Some(floor) = slot.floor {
                snap.floors.push((SlotAddr::from_key(k.value())?, floor));
            }
        }
        for item in tombstones.iter()? {
            let (k, v) = item?;
            snap.tombstones
                .push((hex::encode(k.value()), hex::encode(v.value())));
        }
        Ok(snap)
    }

    fn meta(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta.get(name)?.map(|v| v.value().to_vec()))
    }

    fn winner_count(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        let log = tx.open_table(LOG)?;
        Ok(log.len()?)
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
        let store = RedbStore::open(&dir.path().join("events.redb")).unwrap();
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
        let store = RedbStore::open(&dir.path().join("events.redb")).unwrap();
        let snap = store.snapshot().unwrap();
        assert_eq!(snap.winners, vec![e3, e4]);
        assert_eq!(store.meta("members").unwrap(), Some(b"[]".to_vec()));
    }
}
