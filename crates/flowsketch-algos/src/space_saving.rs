//! SpaceSaving (Metwally, Agrawal, El Abbadi): top-k / heavy hitters with a
//! bounded set of tracked candidates.
//!
//! Error model: for capacity `c`, every tracked key's count is an upper
//! bound on its true count, overestimated by at most its recorded `error`;
//! any key with true count > N/c is guaranteed to be tracked.
//!
//! Merging follows the mergeable-summaries construction: counts of shared
//! keys add; a key present in only one summary is charged the other
//! summary's minimum count as additional potential error; the union is then
//! trimmed back to capacity.

use std::collections::HashMap;

use flowsketch_core::hash::{hash64, HashSpec};
use flowsketch_core::snapshot::{
    algorithm_id, read_snapshot, write_snapshot, Reader, SnapshotHeader, Writer, SNAPSHOT_VERSION,
};
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "spacesaving";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Upper-bound count for this key.
    pub count: u64,
    /// Maximum possible overestimation of `count`.
    pub error: u64,
}

impl Entry {
    /// Guaranteed (lower-bound) count.
    pub fn guaranteed(&self) -> u64 {
        self.count - self.error
    }
}

#[derive(Debug, Clone)]
pub struct SpaceSaving {
    capacity: usize,
    hash: HashSpec,
    /// Stable arena slots own each key exactly once. Slot indices never move,
    /// so the heap can compare and swap integers instead of re-hashing keys.
    slots: Vec<Slot>,
    /// Exact lookup keyed by a deterministic 64-bit digest. The common case
    /// stores one slot inline; true digest collisions retain an exact vector
    /// and compare key bytes before updating.
    key_index: HashMap<u64, IndexBucket>,
    /// Binary min-heap of slot indices.
    min_heap: Vec<usize>,
    total_weight: u64,
    updates: u64,
}

#[derive(Debug, Clone)]
struct Slot {
    key: Vec<u8>,
    digest: u64,
    entry: Entry,
    heap_index: usize,
}

#[derive(Debug, Clone)]
enum IndexBucket {
    One(usize),
    Many(Vec<usize>),
}

impl SpaceSaving {
    pub fn new(capacity: usize, hash: HashSpec) -> Result<Self, SketchError> {
        if capacity == 0 {
            return Err(SketchError::InvalidParam(
                "spacesaving capacity must be positive".into(),
            ));
        }
        Ok(SpaceSaving {
            capacity,
            hash,
            slots: Vec::with_capacity(capacity),
            key_index: HashMap::with_capacity(capacity),
            min_heap: Vec::with_capacity(capacity),
            total_weight: 0,
            updates: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }
    pub fn len(&self) -> usize {
        self.slots.len()
    }
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Additive error bound: any tracked count overestimates by at most
    /// `total_weight / capacity`.
    pub fn epsilon(&self) -> f64 {
        1.0 / self.capacity as f64
    }

    #[inline]
    fn key_digest(&self, key: &[u8]) -> u64 {
        // This index is an implementation detail, not sketch state. Domain
        // separation keeps it independent from hashes used by other sketches.
        hash64(key, self.hash.seed ^ 0x5350_4143_4553_4156)
    }

    #[inline]
    fn find_slot_with_digest(&self, key: &[u8], digest: u64) -> Option<usize> {
        match self.key_index.get(&digest)? {
            IndexBucket::One(index) => (self.slots[*index].key.as_slice() == key).then_some(*index),
            IndexBucket::Many(indices) => indices
                .iter()
                .copied()
                .find(|index| self.slots[*index].key.as_slice() == key),
        }
    }

    #[inline]
    fn find_slot(&self, key: &[u8]) -> Option<usize> {
        self.find_slot_with_digest(key, self.key_digest(key))
    }

    fn add_to_index(&mut self, digest: u64, slot_index: usize) {
        use std::collections::hash_map::Entry as HashMapEntry;

        match self.key_index.entry(digest) {
            HashMapEntry::Vacant(entry) => {
                entry.insert(IndexBucket::One(slot_index));
            }
            HashMapEntry::Occupied(mut entry) => match entry.get_mut() {
                bucket @ IndexBucket::One(_) => {
                    let IndexBucket::One(existing) = *bucket else {
                        unreachable!();
                    };
                    *bucket = IndexBucket::Many(vec![existing, slot_index]);
                }
                IndexBucket::Many(indices) => indices.push(slot_index),
            },
        }
    }

    fn remove_from_index(&mut self, digest: u64, slot_index: usize) {
        let remove_bucket = {
            let bucket = self
                .key_index
                .get_mut(&digest)
                .expect("slot digest must exist in key index");
            match bucket {
                IndexBucket::One(existing) => {
                    debug_assert_eq!(*existing, slot_index);
                    true
                }
                IndexBucket::Many(indices) => {
                    let position = indices
                        .iter()
                        .position(|index| *index == slot_index)
                        .expect("slot must exist in collision bucket");
                    indices.swap_remove(position);
                    if indices.len() == 1 {
                        *bucket = IndexBucket::One(indices[0]);
                    }
                    false
                }
            }
        };
        if remove_bucket {
            self.key_index.remove(&digest);
        }
    }

    #[inline]
    fn slot_is_less(&self, left: usize, right: usize) -> bool {
        let left = &self.slots[left];
        let right = &self.slots[right];
        left.entry
            .count
            .cmp(&right.entry.count)
            .then_with(|| left.digest.cmp(&right.digest))
            .then_with(|| left.key.cmp(&right.key))
            .is_lt()
    }

    #[inline]
    fn heap_slot_is_less(&self, left: usize, right: usize) -> bool {
        self.slot_is_less(self.min_heap[left], self.min_heap[right])
    }

    #[inline]
    fn swap_heap(&mut self, left: usize, right: usize) {
        self.min_heap.swap(left, right);
        self.slots[self.min_heap[left]].heap_index = left;
        self.slots[self.min_heap[right]].heap_index = right;
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if !self.heap_slot_is_less(index, parent) {
                break;
            }
            self.swap_heap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.min_heap.len() {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.min_heap.len() && self.heap_slot_is_less(right, left) {
                right
            } else {
                left
            };
            if !self.heap_slot_is_less(smallest, index) {
                break;
            }
            self.swap_heap(index, smallest);
            index = smallest;
        }
    }

    fn insert_entry(&mut self, key: Vec<u8>, count: u64, error: u64) {
        let digest = self.key_digest(&key);
        self.insert_entry_with_digest(key, digest, count, error);
    }

    fn insert_entry_with_digest(&mut self, key: Vec<u8>, digest: u64, count: u64, error: u64) {
        debug_assert!(self.find_slot_with_digest(&key, digest).is_none());
        let slot_index = self.slots.len();
        let heap_index = self.min_heap.len();
        self.slots.push(Slot {
            key,
            digest,
            entry: Entry { count, error },
            heap_index,
        });
        self.add_to_index(digest, slot_index);
        self.min_heap.push(slot_index);
        self.sift_up(heap_index);
    }

    fn replace_min(&mut self, key: Vec<u8>, digest: u64, count: u64, error: u64) -> Vec<u8> {
        let slot_index = *self.min_heap.first().expect("capacity > 0");
        let old_digest = self.slots[slot_index].digest;
        self.remove_from_index(old_digest, slot_index);

        debug_assert!(self.find_slot_with_digest(&key, digest).is_none());
        let old_key = {
            let slot = &mut self.slots[slot_index];
            let old_key = std::mem::replace(&mut slot.key, key);
            slot.digest = digest;
            slot.entry = Entry { count, error };
            old_key
        };
        self.add_to_index(digest, slot_index);
        self.sift_down(0);
        old_key
    }

    #[inline]
    fn minimum_count(&self) -> u64 {
        self.min_heap
            .first()
            .map(|index| self.slots[*index].entry.count)
            .unwrap_or(0)
    }

    pub fn add(&mut self, key: &[u8], weight: u64) {
        self.total_weight += weight;
        self.updates += 1;
        let digest = self.key_digest(key);
        if let Some(slot_index) = self.find_slot_with_digest(key, digest) {
            let slot = &mut self.slots[slot_index];
            slot.entry.count += weight;
            let heap_index = slot.heap_index;
            // Counts only increase, so the node can move down but never up.
            self.sift_down(heap_index);
            return;
        }
        if self.slots.len() < self.capacity {
            self.insert_entry_with_digest(key.to_vec(), digest, weight, 0);
            return;
        }
        // Evict the current minimum and inherit its count as error.
        let minimum = self.minimum_count();
        self.replace_min(key.to_vec(), digest, minimum + weight, minimum);
    }

    /// Add using a caller-owned key scratch buffer.
    ///
    /// If the key is new, the encoded bytes are moved into the summary instead
    /// of copied. `key` is left as an empty scratch buffer for the caller to
    /// reuse on the next event.
    pub fn add_key_buf(&mut self, key: &mut Vec<u8>, weight: u64) {
        self.total_weight += weight;
        self.updates += 1;
        let digest = self.key_digest(key);
        if let Some(slot_index) = self.find_slot_with_digest(key, digest) {
            let slot = &mut self.slots[slot_index];
            slot.entry.count += weight;
            let heap_index = slot.heap_index;
            self.sift_down(heap_index);
            key.clear();
            return;
        }

        if self.slots.len() < self.capacity {
            let mut owned_key = Vec::with_capacity(key.capacity());
            std::mem::swap(&mut owned_key, key);
            self.insert_entry_with_digest(owned_key, digest, weight, 0);
            return;
        }

        // Evict the current minimum and inherit its count as error. Reuse the
        // evicted key allocation as the caller's next scratch buffer.
        let minimum = self.minimum_count();
        let mut owned_key = Vec::with_capacity(key.capacity());
        std::mem::swap(&mut owned_key, key);
        let mut scratch = self.replace_min(owned_key, digest, minimum + weight, minimum);
        scratch.clear();
        *key = scratch;
    }

    pub fn get(&self, key: &[u8]) -> Option<&Entry> {
        self.find_slot(key).map(|index| &self.slots[index].entry)
    }

    /// Tracked keys sorted by count descending, trimmed to `limit`.
    pub fn top_k(&self, limit: usize) -> Vec<(Vec<u8>, Entry)> {
        let mut all: Vec<(Vec<u8>, Entry)> = self
            .slots
            .iter()
            .map(|slot| (slot.key.clone(), slot.entry.clone()))
            .collect();
        all.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        all.truncate(limit);
        all
    }

    fn params_hash(&self) -> u64 {
        hash64(&(self.capacity as u64).to_le_bytes(), 0)
    }

    pub fn to_snapshot(&self, window_start_nanos: u64, window_end_nanos: u64) -> Vec<u8> {
        let mut params = Writer::new();
        params.u64(self.capacity as u64);
        let mut payload = Writer::new();
        payload.u64(self.total_weight);
        payload.u64(self.updates);
        payload.u32(self.slots.len() as u32);
        // Deterministic order for byte-stable snapshots.
        let mut indices: Vec<usize> = (0..self.slots.len()).collect();
        indices.sort_by(|left, right| self.slots[*left].key.cmp(&self.slots[*right].key));
        for index in indices {
            let slot = &self.slots[index];
            payload.lp_bytes(&slot.key);
            payload.u64(slot.entry.count);
            payload.u64(slot.entry.error);
        }
        write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::SPACE_SAVING,
                hash: self.hash,
                window_start_nanos,
                window_end_nanos,
            },
            &params.buf,
            &payload.buf,
        )
    }

    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, SketchError> {
        let (header, params, payload) = read_snapshot(bytes)?;
        if header.algorithm_id != algorithm_id::SPACE_SAVING {
            return Err(SketchError::Snapshot("not a spacesaving snapshot".into()));
        }
        let mut p = Reader::new(&params);
        let encoded_capacity = p.u64()?;
        let capacity = usize::try_from(encoded_capacity).map_err(|_| {
            SketchError::Snapshot(format!(
                "spacesaving snapshot capacity {encoded_capacity} does not fit this platform"
            ))
        })?;
        if capacity == 0 {
            return Err(SketchError::Snapshot(
                "spacesaving snapshot capacity must be positive".into(),
            ));
        }
        let mut r = Reader::new(&payload);
        let total_weight = r.u64()?;
        let updates = r.u64()?;
        let n = r.u32()? as usize;
        if n > capacity {
            return Err(SketchError::Snapshot(format!(
                "spacesaving snapshot entry count {n} exceeds capacity {capacity}"
            )));
        }
        // Each entry encodes at least a u32 key length + count + error.
        r.check_count(n, 4 + 8 + 8)?;
        let mut summary = SpaceSaving::new(capacity, header.hash)?;
        summary.total_weight = total_weight;
        summary.updates = updates;
        for _ in 0..n {
            let key = r.lp_bytes()?.to_vec();
            let count = r.u64()?;
            let error = r.u64()?;
            if error > count {
                return Err(SketchError::Snapshot(format!(
                    "spacesaving snapshot entry error {error} exceeds count {count}"
                )));
            }
            let digest = summary.key_digest(&key);
            if summary.find_slot_with_digest(&key, digest).is_some() {
                return Err(SketchError::Snapshot(
                    "spacesaving snapshot contains a duplicate key".into(),
                ));
            }
            summary.insert_entry_with_digest(key, digest, count, error);
        }
        Ok(summary)
    }
}

impl Sketch for SpaceSaving {
    fn update(&mut self, key: &[u8], value: u64) {
        self.add(key, value);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.get(key).map(|entry| entry.count as f64).unwrap_or(0.0)
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        self.compatibility()
            .ensure_matches(&other.compatibility())?;
        let self_min = if self.slots.len() >= self.capacity {
            self.minimum_count()
        } else {
            0
        };
        let other_min = if other.slots.len() >= other.capacity {
            other.minimum_count()
        } else {
            0
        };

        let mut merged = Vec::with_capacity(self.slots.len() + other.slots.len());
        for slot in &self.slots {
            let (other_count, other_error) = match other.get(&slot.key) {
                Some(other_entry) => (other_entry.count, other_entry.error),
                None => (other_min, other_min),
            };
            merged.push((
                slot.key.clone(),
                Entry {
                    count: slot.entry.count + other_count,
                    error: slot.entry.error + other_error,
                },
            ));
        }
        for slot in &other.slots {
            if self.get(&slot.key).is_none() {
                merged.push((
                    slot.key.clone(),
                    Entry {
                        count: slot.entry.count + self_min,
                        error: slot.entry.error + self_min,
                    },
                ));
            }
        }
        // Trim back to capacity, keeping the largest counts.
        merged.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        merged.truncate(self.capacity);

        self.slots.clear();
        self.key_index.clear();
        self.min_heap.clear();
        for (key, entry) in merged {
            self.insert_entry(key, entry.count, entry.error);
        }
        self.total_weight += other.total_weight;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let slot_bytes = self.slots.capacity() * std::mem::size_of::<Slot>()
            + self
                .slots
                .iter()
                .map(|slot| slot.key.capacity())
                .sum::<usize>();
        let index_bytes = self.key_index.capacity()
            * (std::mem::size_of::<u64>() + std::mem::size_of::<IndexBucket>() + 1)
            + self
                .key_index
                .values()
                .map(|bucket| match bucket {
                    IndexBucket::One(_) => 0,
                    IndexBucket::Many(indices) => indices.capacity() * std::mem::size_of::<usize>(),
                })
                .sum::<usize>();
        let heap_bytes = self.min_heap.capacity() * std::mem::size_of::<usize>();
        slot_bytes + index_bytes + heap_bytes + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.slots.clear();
        self.key_index.clear();
        self.min_heap.clear();
        self.total_weight = 0;
        self.updates = 0;
    }

    fn update_count(&self) -> u64 {
        self.updates
    }

    fn compatibility(&self) -> SketchCompatibility {
        SketchCompatibility {
            algorithm: ALGORITHM.to_string(),
            version: 1,
            hash: self.hash,
            params_hash: self.params_hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_heap_consistent(summary: &SpaceSaving) {
        assert_eq!(summary.min_heap.len(), summary.slots.len());
        let mut seen = vec![false; summary.slots.len()];
        for (index, slot_index) in summary.min_heap.iter().copied().enumerate() {
            let slot = &summary.slots[slot_index];
            assert!(!seen[slot_index], "slot {slot_index} appears twice in heap");
            seen[slot_index] = true;
            assert_eq!(
                slot.heap_index, index,
                "wrong heap index for {:?}",
                slot.key
            );
            assert_eq!(summary.find_slot(&slot.key), Some(slot_index));
            for child in [index * 2 + 1, index * 2 + 2] {
                if child < summary.min_heap.len() {
                    assert!(
                        !summary.heap_slot_is_less(child, index),
                        "child at {child} sorts below parent at {index}"
                    );
                }
            }
        }
        assert!(seen.into_iter().all(|present| present));
    }

    #[test]
    fn tracks_heavy_hitters_exactly_when_under_capacity() {
        let mut s = SpaceSaving::new(100, HashSpec::new(1)).unwrap();
        for i in 0..50u32 {
            for _ in 0..=i {
                s.add(format!("k{i}").as_bytes(), 1);
            }
        }
        let top = s.top_k(3);
        assert_eq!(top[0].0, b"k49".to_vec());
        assert_eq!(top[0].1.count, 50);
        assert_eq!(top[0].1.error, 0);
    }

    #[test]
    fn count_is_upper_bound_and_guarantee_holds() {
        let mut s = SpaceSaving::new(50, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        // Zipf-ish: key i gets ~ 10000/i updates.
        for i in 1..=500u64 {
            let reps = 10_000 / i;
            for _ in 0..reps {
                s.add(format!("k{i}").as_bytes(), 1);
                *exact.entry(format!("k{i}")).or_insert(0) += 1;
            }
        }
        for (key, e) in s.top_k(50) {
            let k = String::from_utf8(key).unwrap();
            let truth = exact.get(&k).copied().unwrap_or(0);
            assert!(e.count >= truth, "{k}: count {} < truth {truth}", e.count);
            assert!(e.guaranteed() <= truth, "{k}: guaranteed too high");
        }
        // The heaviest keys must be present.
        for i in 1..=5u64 {
            assert!(s.get(format!("k{i}").as_bytes()).is_some());
        }
    }

    #[test]
    fn add_key_buf_matches_borrowed_add_and_reuses_scratch() {
        let mut borrowed = SpaceSaving::new(5, HashSpec::new(1)).unwrap();
        let mut owned = SpaceSaving::new(5, HashSpec::new(1)).unwrap();
        let mut scratch = Vec::with_capacity(64);

        for i in 0..100u32 {
            let key = format!("k{}", i % 13);
            let weight = (i % 7 + 1) as u64;
            borrowed.add(key.as_bytes(), weight);

            scratch.extend_from_slice(key.as_bytes());
            owned.add_key_buf(&mut scratch, weight);
            assert!(scratch.is_empty());
            assert!(scratch.capacity() >= key.len());
        }

        assert_eq!(borrowed.top_k(5), owned.top_k(5));
        assert_eq!(borrowed.total_weight(), owned.total_weight());
    }

    #[test]
    fn indexed_heap_stays_consistent_under_hot_updates_and_evictions() {
        let mut summary = SpaceSaving::new(256, HashSpec::new(9)).unwrap();
        for index in 0..100_000u64 {
            // Mix a hot head with sustained churn beyond capacity.
            let key = if index % 3 == 0 {
                format!("hot-{}", index % 17)
            } else {
                format!("churn-{}", index % 4_096)
            };
            summary.add(key.as_bytes(), index % 5 + 1);
            if index % 997 == 0 {
                assert_heap_consistent(&summary);
            }
        }
        assert_heap_consistent(&summary);
        assert_eq!(summary.min_heap.len(), summary.capacity());
    }

    #[test]
    fn merge_preserves_upper_bound_property() {
        let mut a = SpaceSaving::new(20, HashSpec::new(1)).unwrap();
        let mut b = SpaceSaving::new(20, HashSpec::new(1)).unwrap();
        let mut exact: HashMap<String, u64> = HashMap::new();
        for i in 1..=100u64 {
            let reps = 2_000 / i;
            for r in 0..reps {
                let key = format!("k{i}");
                *exact.entry(key.clone()).or_insert(0) += 1;
                if r % 2 == 0 {
                    a.add(key.as_bytes(), 1);
                } else {
                    b.add(key.as_bytes(), 1);
                }
            }
        }
        a.merge_from(&b).unwrap();
        assert!(a.len() <= 20);
        for (key, e) in a.top_k(20) {
            let k = String::from_utf8(key).unwrap();
            let truth = exact.get(&k).copied().unwrap_or(0);
            assert!(
                e.count >= truth,
                "{k}: merged count {} < truth {truth}",
                e.count
            );
        }
        assert_eq!(a.total_weight(), exact.values().sum::<u64>());
    }

    #[test]
    fn hostile_snapshot_params_are_rejected() {
        let craft = |capacity: u64, n: u32| {
            let mut params = Writer::new();
            params.u64(capacity);
            let mut payload = Writer::new();
            payload.u64(0); // total_weight
            payload.u64(0); // updates
            payload.u32(n);
            write_snapshot(
                &SnapshotHeader {
                    version: SNAPSHOT_VERSION,
                    algorithm_id: algorithm_id::SPACE_SAVING,
                    hash: HashSpec::new(1),
                    window_start_nanos: 0,
                    window_end_nanos: 0,
                },
                &params.buf,
                &payload.buf,
            )
        };
        // Zero capacity breaks the eviction invariant; an entry count the
        // payload cannot back must fail before the map is preallocated.
        assert!(SpaceSaving::from_snapshot(&craft(0, 0)).is_err());
        #[cfg(target_pointer_width = "32")]
        assert!(SpaceSaving::from_snapshot(&craft(u64::MAX, 0)).is_err());
        let err = SpaceSaving::from_snapshot(&craft(1, 2)).unwrap_err();
        assert!(err.to_string().contains("exceeds capacity"), "{err}");
        assert!(SpaceSaving::from_snapshot(&craft(10, u32::MAX)).is_err());
    }

    #[test]
    fn snapshot_entry_error_cannot_exceed_count() {
        let mut params = Writer::new();
        params.u64(1);
        let mut payload = Writer::new();
        payload.u64(1); // total_weight
        payload.u64(1); // updates
        payload.u32(1);
        payload.lp_bytes(b"key");
        payload.u64(1); // count
        payload.u64(2); // error
        let bytes = write_snapshot(
            &SnapshotHeader {
                version: SNAPSHOT_VERSION,
                algorithm_id: algorithm_id::SPACE_SAVING,
                hash: HashSpec::new(1),
                window_start_nanos: 0,
                window_end_nanos: 0,
            },
            &params.buf,
            &payload.buf,
        );
        let err = SpaceSaving::from_snapshot(&bytes).unwrap_err();
        assert!(err.to_string().contains("exceeds count"), "{err}");
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s = SpaceSaving::new(10, HashSpec::new(2)).unwrap();
        for i in 0..100u32 {
            s.add(format!("k{}", i % 15).as_bytes(), (i % 3 + 1) as u64);
        }
        let s2 = SpaceSaving::from_snapshot(&s.to_snapshot(0, 1)).unwrap();
        assert_eq!(s.top_k(10), s2.top_k(10));
        assert_eq!(s.total_weight(), s2.total_weight());
    }
}
