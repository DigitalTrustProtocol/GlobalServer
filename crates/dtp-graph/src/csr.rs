//! Packed runs: the immutable base CSR (dense offsets, the layout that will
//! be memory-mapped from segment files) and the per-node delta runs.
//!
//! Both store, per node, entries grouped by bucket and sorted by
//! `(bucket, peer node, edge id)`, with a parallel edge-id array and a bucket
//! directory. Readers see `(Entry, EdgeId)` pairs and never care which tier
//! they come from.

use crate::entry::Entry;
use crate::{BucketId, EdgeId, NodeId};

/// One bucket's range inside a node's run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub bucket: BucketId,
    pub start: u32,
    pub end: u32,
}

/// A borrowed slice of one bucket of one node.
#[derive(Clone, Copy, Debug)]
pub struct RunSlice<'a> {
    pub entries: &'a [u32],
    pub ids: &'a [u32],
}

impl<'a> RunSlice<'a> {
    pub const EMPTY: RunSlice<'static> = RunSlice {
        entries: &[],
        ids: &[],
    };

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(self) -> impl Iterator<Item = (Entry, EdgeId)> + 'a {
        let ids = self.ids;
        self.entries
            .iter()
            .zip(ids.iter())
            .map(|(&e, &id)| (Entry(e), id))
    }
}

/// Recomputes sibling bits over entries sorted by peer node within one bucket.
fn mark_siblings(entries: &mut [u32]) {
    let mut i = 0;
    while i < entries.len() {
        let node = Entry(entries[i]).node();
        let mut j = i + 1;
        while j < entries.len() && Entry(entries[j]).node() == node {
            j += 1;
        }
        let siblings = j - i > 1;
        for e in &mut entries[i..j] {
            *e = Entry(*e).with_siblings(siblings).0;
        }
        i = j;
    }
}

/// A delta run for one node (RAM tier, copy-on-write per node per epoch).
#[derive(Clone, Debug, Default)]
pub struct Run {
    pub dir: Vec<DirEntry>,
    pub entries: Vec<u32>,
    pub ids: Vec<u32>,
}

impl Run {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn bucket(&self, bucket: BucketId) -> RunSlice<'_> {
        match self.dir.binary_search_by_key(&bucket, |d| d.bucket) {
            Ok(i) => {
                let d = self.dir[i];
                RunSlice {
                    entries: &self.entries[d.start as usize..d.end as usize],
                    ids: &self.ids[d.start as usize..d.end as usize],
                }
            }
            Err(_) => RunSlice::EMPTY,
        }
    }

    pub fn buckets(&self) -> impl Iterator<Item = BucketId> + '_ {
        self.dir.iter().map(|d| d.bucket)
    }

    fn shift_after(&mut self, from_dir: usize, delta: i64) {
        for d in &mut self.dir[from_dir..] {
            d.start = (i64::from(d.start) + delta) as u32;
            d.end = (i64::from(d.end) + delta) as u32;
        }
    }

    /// Inserts an entry keeping `(bucket, node, edge id)` order.
    pub fn insert(&mut self, bucket: BucketId, entry: Entry, id: EdgeId) {
        let di = match self.dir.binary_search_by_key(&bucket, |d| d.bucket) {
            Ok(i) => i,
            Err(i) => {
                let pos = if i == 0 { 0 } else { self.dir[i - 1].end };
                self.dir.insert(
                    i,
                    DirEntry {
                        bucket,
                        start: pos,
                        end: pos,
                    },
                );
                i
            }
        };
        let d = self.dir[di];
        let (start, end) = (d.start as usize, d.end as usize);
        let key = (entry.node(), id);
        let offset = self.entries[start..end]
            .iter()
            .zip(&self.ids[start..end])
            .position(|(&e, &i)| (Entry(e).node(), i) > key)
            .unwrap_or(end - start);
        let pos = start + offset;
        self.entries.insert(pos, entry.0);
        self.ids.insert(pos, id);
        self.dir[di].end += 1;
        self.shift_after(di + 1, 1);
        let d = self.dir[di];
        mark_siblings(&mut self.entries[d.start as usize..d.end as usize]);
    }

    /// Removes the entry with `id` from `bucket`; returns whether it existed.
    pub fn remove(&mut self, bucket: BucketId, id: EdgeId) -> bool {
        let Ok(di) = self.dir.binary_search_by_key(&bucket, |d| d.bucket) else {
            return false;
        };
        let d = self.dir[di];
        let Some(offset) = self.ids[d.start as usize..d.end as usize]
            .iter()
            .position(|&i| i == id)
        else {
            return false;
        };
        let pos = d.start as usize + offset;
        self.entries.remove(pos);
        self.ids.remove(pos);
        self.dir[di].end -= 1;
        self.shift_after(di + 1, -1);
        if self.dir[di].start == self.dir[di].end {
            self.dir.remove(di);
        } else {
            let d = self.dir[di];
            mark_siblings(&mut self.entries[d.start as usize..d.end as usize]);
        }
        true
    }
}

/// Immutable base CSR with dense per-node directory offsets.
#[derive(Clone, Debug, Default)]
pub struct Csr {
    /// `dir_offsets[n]..dir_offsets[n + 1]` indexes `dir` for node `n`.
    pub dir_offsets: Vec<u32>,
    pub dir: Vec<DirEntry>,
    pub entries: Vec<u32>,
    pub ids: Vec<u32>,
}

impl Csr {
    pub fn node_count(&self) -> usize {
        self.dir_offsets.len().saturating_sub(1)
    }

    fn node_dir(&self, node: NodeId) -> &[DirEntry] {
        let n = node as usize;
        if n + 1 >= self.dir_offsets.len() {
            return &[];
        }
        &self.dir[self.dir_offsets[n] as usize..self.dir_offsets[n + 1] as usize]
    }

    pub fn bucket(&self, node: NodeId, bucket: BucketId) -> RunSlice<'_> {
        let dir = self.node_dir(node);
        match dir.binary_search_by_key(&bucket, |d| d.bucket) {
            Ok(i) => {
                let d = dir[i];
                RunSlice {
                    entries: &self.entries[d.start as usize..d.end as usize],
                    ids: &self.ids[d.start as usize..d.end as usize],
                }
            }
            Err(_) => RunSlice::EMPTY,
        }
    }

    pub fn buckets(&self, node: NodeId) -> impl Iterator<Item = BucketId> + '_ {
        self.node_dir(node).iter().map(|d| d.bucket)
    }

    pub fn node_len(&self, node: NodeId) -> usize {
        self.node_dir(node)
            .iter()
            .map(|d| (d.end - d.start) as usize)
            .sum()
    }

    /// Builds a CSR from per-node `(bucket, entry, id)` lists.
    pub fn build(node_count: usize, mut per_node: Vec<Vec<(BucketId, Entry, EdgeId)>>) -> Csr {
        per_node.resize_with(node_count, Vec::new);
        let mut csr = Csr {
            dir_offsets: Vec::with_capacity(node_count + 1),
            ..Default::default()
        };
        csr.dir_offsets.push(0);
        for items in &mut per_node {
            items.sort_by_key(|(b, e, id)| (*b, e.node(), *id));
            let mut i = 0;
            while i < items.len() {
                let bucket = items[i].0;
                let start = csr.entries.len() as u32;
                while i < items.len() && items[i].0 == bucket {
                    csr.entries.push(items[i].1.with_siblings(false).0);
                    csr.ids.push(items[i].2);
                    i += 1;
                }
                let end = csr.entries.len() as u32;
                mark_siblings(&mut csr.entries[start as usize..end as usize]);
                csr.dir.push(DirEntry { bucket, start, end });
            }
            csr.dir_offsets.push(csr.dir.len() as u32);
        }
        csr
    }

    pub fn bytes(&self) -> usize {
        self.dir_offsets.len() * 4 + self.dir.len() * 12 + self.entries.len() * 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(node: NodeId) -> Entry {
        Entry::pack(node, 1, false, false)
    }

    #[test]
    fn run_insert_remove_keeps_order_and_siblings() {
        let mut run = Run::default();
        run.insert(5, e(3), 10);
        run.insert(2, e(9), 11);
        run.insert(5, e(1), 12);
        run.insert(5, e(3), 13);
        assert_eq!(run.buckets().collect::<Vec<_>>(), vec![2, 5]);
        let b5: Vec<_> = run
            .bucket(5)
            .iter()
            .map(|(e, id)| (e.node(), id, e.has_siblings()))
            .collect();
        assert_eq!(b5, vec![(1, 12, false), (3, 10, true), (3, 13, true)]);
        assert!(run.remove(5, 10));
        let b5: Vec<_> = run
            .bucket(5)
            .iter()
            .map(|(e, id)| (e.node(), id, e.has_siblings()))
            .collect();
        assert_eq!(b5, vec![(1, 12, false), (3, 13, false)]);
        assert!(run.remove(2, 11));
        assert_eq!(run.buckets().collect::<Vec<_>>(), vec![5]);
        assert!(!run.remove(2, 11));
        assert_eq!(run.bucket(5).len(), 2);
    }

    #[test]
    fn csr_build_and_read() {
        let csr = Csr::build(
            3,
            vec![
                vec![(1, e(2), 0), (0, e(1), 1), (1, e(2), 2)],
                vec![],
                vec![(0, e(0), 3)],
            ],
        );
        assert_eq!(csr.node_count(), 3);
        assert_eq!(csr.buckets(0).collect::<Vec<_>>(), vec![0, 1]);
        let b1: Vec<_> = csr
            .bucket(0, 1)
            .iter()
            .map(|(e, id)| (e.node(), id, e.has_siblings()))
            .collect();
        assert_eq!(b1, vec![(2, 0, true), (2, 2, true)]);
        assert!(csr.bucket(1, 0).is_empty());
        assert_eq!(csr.bucket(2, 0).len(), 1);
        assert!(csr.bucket(7, 0).is_empty());
        assert_eq!(csr.node_len(0), 3);
    }
}
