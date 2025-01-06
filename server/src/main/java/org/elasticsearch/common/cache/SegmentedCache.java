/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.common.cache;

import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.Releasable;
import org.elasticsearch.core.Tuple;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;
import java.util.function.ToLongBiFunction;

/**
 * A cache that segments entries according to a provided id, but maintains a size and eviction policy for the cache as a whole.
 * The segmentation makes it efficient to remove or traverse all entries for a particular segment without needing to maintain multiple
 * independent caches.
 * @param <S> The type of the segment-id
 * @param <K> The type of the cache key. The same key may exist in multiple segments.
 * @param <V> The value to be cached.
 */
public class SegmentedCache<S, K, V> {

    private static final ToLongBiFunction<Object, Object> DEFAULT_WEIGHER = (k, v) -> 1;

    private final Map<S, Segment> segments = new ConcurrentHashMap<>();
    private final StatCounter cacheStats = new StatCounter();

    private final ToLongBiFunction<? super K, ? super V> weigher;
    private final long maxWeight;

    public static class Expiry {
        private final long accessNanos;
        private final long writeNanos;

        public Expiry(long accessNanos, long writeNanos) {
            this.accessNanos = accessNanos;
            this.writeNanos = writeNanos;
        }
    }

    @Nullable
    private final Expiry expiry;
    private final LongSupplier timestamp;

    @Nullable
    private final RemovalListener<Tuple<S, K>, V> removalListener;

    private final EntryList entries = new EntryList();

    public SegmentedCache() {
        this(DEFAULT_WEIGHER, -1, null, null);
    }

    public SegmentedCache(
        ToLongBiFunction<? super K, ? super V> weigher,
        long maxWeight,
        Expiry expiry,
        RemovalListener<Tuple<S, K>, V> removalListener
    ) {
        this(weigher, maxWeight, expiry, removalListener, expiry == null ? () -> 0L : System::nanoTime);
    }

    SegmentedCache(
        ToLongBiFunction<? super K, ? super V> weigher,
        long maxWeight,
        Expiry expiry,
        RemovalListener<Tuple<S, K>, V> removalListener,
        LongSupplier timestampSupplier
    ) {
        this.weigher = weigher == null ? DEFAULT_WEIGHER : weigher;
        this.maxWeight = maxWeight;
        this.expiry = expiry;
        this.removalListener = removalListener;
        this.timestamp = timestampSupplier;
    }

    public int count() {
        return entries.count;
    }

    public long weight() {
        return entries.weight;
    }

    /**
     * Returns the value to which the specified key is mapped, or null if this map contains no mapping for the key.
     *
     * @param key the key whose associated value is to be returned
     * @return the value to which the specified key is mapped, or null if this map contains no mapping for the key
     */
    public V get(S segment, K key) {
        return get(segment, key, timestamp.getAsLong());
    }

    public void put(S segment, K key, V value) {
        put(segment, key, value, timestamp.getAsLong());
    }

    public V computeIfAbsent(S segment, K key, CacheLoader<Tuple<S, K>, V> loader) {
        return computeIfAbsent(segment, key, loader, timestamp.getAsLong());
    }

    private V get(S segmentId, K key, long timestamp) {
        final Segment segment = this.segments.get(segmentId);
        if (segment == null) {
            return null;
        }
        final Entry<S, K, V> entry = segment.get(key, timestamp);
        if (entry == null) {
            return null;
        }
        entry.accessTime = timestamp;
        entries.storeAtHead(entry);
        return entry.value;
    }

    public void invalidateAll() {
        final List<Releasable> unlock = new ArrayList<>(segments.size());
        this.entries.entriesLock.lock();
        Entry<S, K, V> head = null;
        try {
            for (Segment segment : segments.values()) {
                unlock.add(segment.lockForWrites());
            }
            for (Segment segment : segments.values()) {
                segment.clear();
            }
            head = entries.clear();
        } finally {
            for (Releasable r : unlock) {
                r.close();
            }
            this.entries.entriesLock.unlock();
        }
        while (head != null) {
            final Segment segment = this.segments.get(head.segmentId);
            removed(head, segment, RemovalNotification.RemovalReason.INVALIDATED);
            head = head.next;
        }
    }

    private void put(S segmentId, K key, V value, long timestamp) {
        final Segment segment = this.segments.computeIfAbsent(segmentId, Segment::new);
        final Tuple<Entry<S, K, V>, Entry<S, K, V>> tupNewOld = segment.put(key, value, timestamp);

        final Entry<S, K, V> newEntry = tupNewOld.v1();
        final Entry<S, K, V> oldEntry = tupNewOld.v2();

        if (oldEntry == null) {
            entries.storeAtHead(newEntry);
        } else {
            entries.replace(oldEntry, newEntry);
        }
    }

    private V computeIfAbsent(S segmentId, K key, CacheLoader<Tuple<S, K>, V> loader, long timestamp) {
        final Segment segment = this.segments.computeIfAbsent(segmentId, Segment::new);
        final Entry<S, K, V> entry = segment.computeIfAbsent(key, loader, timestamp);
        entries.storeAtHead(entry);
        return entry.value;
    }

    private boolean isExpired(Entry<S, K, V> entry, long currentTime) {
        if (expiry == null) {
            return false;
        }
        if (expiry.accessNanos != -1 && currentTime - entry.accessTime > expiry.accessNanos) {
            return true;
        }
        if (expiry.writeNanos != -1 && currentTime - entry.writeTime > expiry.writeNanos) {
            return true;
        }
        return false;
    }

    private void removed(Entry<S, K, V> entry, Segment segment, RemovalNotification.RemovalReason reason) {
        segment.segmentStats.removal(reason);
        cacheStats.removal(reason);
        notifyRemoved(entry, reason);
    }

    private void notifyRemoved(Entry<S, K, V> entry, RemovalNotification.RemovalReason reason) {
        if (removalListener != null) {
            removalListener.onRemoval(new RemovalNotification<>(new Tuple<>(entry.segmentId, entry.key), entry.value, reason));
        }
    }

    private static class StatCounter {
        private final LongAdder hits = new LongAdder();
        private final LongAdder misses = new LongAdder();
        private final LongAdder writes = new LongAdder();
        private final LongAdder evictions = new LongAdder();
        private final LongAdder invalidations = new LongAdder();

        private void miss() {
            this.misses.increment();
        }

        private void removal(RemovalNotification.RemovalReason reason) {
            switch (reason) {
                case RemovalNotification.RemovalReason.EVICTED -> evictions.increment();
                case INVALIDATED -> invalidations.increment();
                case REPLACED -> {
                    // no stats needed
                }
            }
        }

        private void hit() {
            this.hits.increment();
        }

        public void write() {
            this.writes.increment();
        }
    }

    private enum EntryState {
        NEW,
        ACTIVE,
        REMOVED
    }

    private static class Entry<S, K, V> {
        private final S segmentId;
        private final K key;
        private final V value;

        private final long writeTime;
        private long accessTime;

        public Entry<S, K, V> previous;
        public Entry<S, K, V> next;
        public EntryState state;

        Entry(S segmentId, K key, V value, long timestamp) {
            this.segmentId = Objects.requireNonNull(segmentId);
            this.key = Objects.requireNonNull(key);
            this.value = Objects.requireNonNull(value);
            this.writeTime = timestamp;
            this.accessTime = timestamp;
            this.previous = null;
            this.next = null;
            this.state = EntryState.NEW;
        }

        @Override
        public String toString() {
            return SegmentedCache.class.getSimpleName()
                + "."
                + getClass().getSimpleName()
                + "<"
                + key
                + ","
                + value
                + ">{a="
                + accessTime
                + ",w="
                + writeTime
                + ",s="
                + state
                + ",p="
                + (previous == null ? null : "k:" + previous.key + ",a:" + previous.accessTime)
                + ",n="
                + (next == null ? null : "k:" + next.key + ",a:" + next.accessTime)
                + "}@"
                + Long.toHexString(System.identityHashCode(this));
        }

        public boolean isNew() {
            if (this.state == EntryState.NEW) {
                assert this.previous == null : this;
                assert this.next == null : this;
                return true;
            } else {
                return false;
            }
        }
    }

    private class EntryList {

        private final ReentrantLock entriesLock = new ReentrantLock();
        private Entry<S, K, V> head, tail;

        private int count = 0;
        private long weight = 0;

        private void storeAtHead(Entry<S, K, V> entry) {
            entriesLock.lock();
            try {
                _store(entry);
            } finally {
                entriesLock.unlock();
            }
        }

        private void _store(Entry<S, K, V> entry) {
            switch (entry.state) {
                case REMOVED -> {
                    // Already removed, ignore
                }
                case ACTIVE -> {
                    _move(entry);
                }
                case NEW -> {
                    _putNew(entry);
                    prune();
                }
            }
            assert assertConsistent();
        }

        private void _move(Entry<S, K, V> entry) {
            assert entriesLock.isHeldByCurrentThread();
            assert head != null : "Cannot move existing entry if LRU is empty";
            entriesLock.lock();
            try {

                if (entry.previous == null) {
                    assert entry == head : "Entry " + entry + " has no previous entry, but is not the head (head=" + head + ")";
                    return;
                }

                if (entry == tail) {
                    tail = entry.previous;
                } else {
                    assert entry.next != null : "Entry must have a next item unless it is the tail";
                    entry.next.previous = entry.previous;
                }

                entry.previous.next = entry.next;
                entry.previous = null;
                entry.next = head;
                head.previous = entry;
                head = entry;
            } finally {
                entriesLock.unlock();
            }

            assert assertConsistent();
        }

        private void _putNew(Entry<S, K, V> entry) {
            assert entriesLock.isHeldByCurrentThread();
            assert entry.previous == null && entry.next == null : "Cannot put existing entry [" + entry + "]";
            assert entry.state == EntryState.NEW : "Entry is not new [" + entry + "]";
            if (head == null) {
                // First entry
                head = tail = entry;
            } else {
                entry.next = head;
                head.previous = entry;
                head = entry;
            }
            entry.state = EntryState.ACTIVE;
            count++;
            weight += weigher.applyAsLong(entry.key, entry.value);
        }

        public void remove(Entry<S, K, V> entry) {
            entriesLock.lock();
            try {
                _remove(entry);
            } finally {
                entriesLock.unlock();
            }
            assert assertConsistent();
        }

        private void _remove(Entry<S, K, V> entry) {
            assert entriesLock.isHeldByCurrentThread();
            assert head != null : "Cannot remove entry from empty LRU";

            switch (entry.state) {
                case REMOVED -> {
                    // Already removed, ignore
                    return;
                }
                case ACTIVE -> {
                    // good
                }
                case NEW -> {
                    // not added yet, just mark it removed
                    entry.state = EntryState.REMOVED;
                    return;
                }
            }

            if (entry == head) {
                head = head.next;
                if (head == null) {
                    assert entry == tail;
                } else {
                    assert head.previous == entry;
                    head.previous = null;
                }
            } else {
                assert entry.previous != null : "Entry (" + entry + ") must have a previous item unless it is the head";
                entry.previous.next = entry.next;
            }

            if (entry == tail) {
                tail = entry.previous;
                if (tail == null) {
                    assert head == null;
                } else {
                    // Should have been handled above
                    assert tail.next == null;
                }
            } else {
                assert entry.next != null : "Entry must have a next item unless it is the tail";
                entry.next.previous = entry.previous;
            }

            entry.state = EntryState.REMOVED;
            count--;
            weight -= weigher.applyAsLong(entry.key, entry.value);

        }

        public void replace(Entry<S, K, V> oldEntry, Entry<S, K, V> newEntry) {
            entriesLock.lock();
            try {
                _remove(oldEntry);
                _store(newEntry);
            } finally {
                entriesLock.unlock();
            }
            assert assertConsistent();
        }

        private void prune() {
            assert entriesLock.isHeldByCurrentThread();
            final long since = timestamp.getAsLong();
            if (maxWeight > 0) {
                while (tail != null && weight > maxWeight) {
                    prune(tail);
                }
            }
            if (expiry != null) {
                while (tail != null && isExpired(tail, since)) {
                    prune(tail);
                }
            }
        }

        private void prune(Entry<S, K, V> entry) {
            assert entriesLock.isHeldByCurrentThread();
            final Segment segment = SegmentedCache.this.segments.get(entry.segmentId);
            assert segment != null;
            segment.remove(entry, RemovalNotification.RemovalReason.EVICTED);
            _remove(entry);
        }

        private boolean assertConsistent() {
            entriesLock.lock();
            try {
                if (head == null) {
                    assert tail == null;
                } else {
                    assert tail.next == null;
                    Entry<S, K, V> previous = null;
                    Entry<S, K, V> entry = head;
                    while (entry != null) {
                        assert entry.previous == previous : "Mismatch " + previous + " -> " + entry;
                        assert entry.state == EntryState.ACTIVE : "Inactive entry " + entry;
                        previous = entry;
                        entry = entry.next;
                    }
                    assert previous == tail;
                }
            } finally {
                entriesLock.unlock();
            }
            return true;
        }

        public Entry<S, K, V> clear() {
            var e = head;
            while (e != null) {
                e.state = EntryState.REMOVED;
                e = e.next;
            }
            var h = head;
            head = tail = null;
            return h;
        }
    }

    private class Segment {
        private final S id;
        private Block[] blocks;

        private final StatCounter segmentStats = new StatCounter();

        private Segment(S id) {
            this.id = id;
            this.blocks = allocateBlocks();
        }

        @SuppressWarnings("unchecked")
        private Block[] allocateBlocks() {
            final int size = 256;
            final Block[] b = (Block[]) Array.newInstance(Block.class, size);
            for (int i = 0; i < size; i++) {
                b[i] = new Block();
            }
            return b;
        }

        public Entry<S, K, V> get(K key, long timestamp) {
            final Block block = getBlock(key);
            final Entry<S, K, V> entry = block.get(key, timestamp, this);
            if (entry == null) {
                segmentStats.miss();
                cacheStats.miss();
            } else {
                segmentStats.hit();
                cacheStats.hit();
            }
            return entry;
        }

        /**
         * @return A {@link Tuple} of {@code ( new_entry, replaced_entry )}
         */
        public Tuple<Entry<S, K, V>, Entry<S, K, V>> put(K key, V value, long timestamp) {
            final Block block = getBlock(key);
            final Tuple<Entry<S, K, V>, Entry<S, K, V>> tuple = block.put(this.id, key, value, timestamp);
            segmentStats.write();
            cacheStats.write();
            return tuple;
        }

        public Entry<S, K, V> computeIfAbsent(K key, CacheLoader<Tuple<S, K>, V> loader, long timestamp) {
            final Block block = getBlock(key);
            Entry<S, K, V> entry = block.computeIfAbsent(this, key, loader, timestamp);
            if (entry.state == EntryState.NEW) {
                segmentStats.write();
                cacheStats.write();
            }
            return entry;
        }

        public void remove(Entry<S, K, V> entry, RemovalNotification.RemovalReason reason) {
            final Block block = getBlock(entry.key);
            if (block.remove(entry)) {
                segmentStats.removal(reason);
                cacheStats.removal(reason);
            }
        }

        private Block getBlock(K key) {
            final int idx = key.hashCode() & 0xff;
            return blocks[idx];
        }

        public void clear() {
            this.blocks = allocateBlocks();
        }

        public Releasable lockForWrites() {
            final AtomicReference<Lock[]> heldLocks = new AtomicReference<>();
            final Releasable unlock = () -> {
                final Lock[] locks = heldLocks.get();
                if (locks != null) {
                    for (var b : locks) {
                        if (b != null) {
                            b.unlock();
                        }
                    }
                }
            };
            try {
                final Lock[] blockLocks = new Lock[blocks.length];
                heldLocks.set(blockLocks);
                for (int i = 0; i < this.blocks.length; i++) {
                    final Lock innerLock = this.blocks[i].blockLock.writeLock();
                    innerLock.lock();
                    blockLocks[i] = innerLock;
                }
            } catch (Throwable t) {
                unlock.close();
                throw t;
            }
            return unlock;
        }
    }

    private final class Block {
        private final ReadWriteLock blockLock = new ReentrantReadWriteLock();

        private Map<K, Entry<S, K, V>> values;
        private Map<K, CompletableFuture<Entry<S, K, V>>> inFlight;

        Block() {
            this.values = null;
            this.inFlight = null;
        }

        public Entry<S, K, V> get(K key, long timestamp, Segment segment) {
            Entry<S, K, V> entry = findEntry(key);
            if (entry == null) {
                return null;
            }
            if (isExpired(entry, timestamp)) {
                return null;
            }
            return entry;
        }

        public Tuple<Entry<S, K, V>, Entry<S, K, V>> put(S segmentId, K key, V value, long timestamp) {
            final Entry<S, K, V> entry = new Entry<>(segmentId, key, value, timestamp);
            Entry<S, K, V> previous;
            final CompletableFuture<Entry<S, K, V>> future;

            final Lock lock = blockLock.writeLock();
            lock.lock();
            try {
                if (values == null) {
                    values = new HashMap<>();
                }
                previous = values.put(key, entry);
                future = inFlight == null ? null : inFlight.remove(key);
            } finally {
                lock.unlock();
            }
            if (previous == null) {
                if (future != null) {
                    if (future.isDone()) {
                        try {
                            previous = future.get();
                        } catch (ExecutionException | InterruptedException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
            }
            if (previous != null) {
                notifyRemoved(previous, RemovalNotification.RemovalReason.REPLACED);
            }
            return new Tuple<>(entry, previous);
        }

        public Entry<S, K, V> computeIfAbsent(Segment segment, K key, CacheLoader<Tuple<S, K>, V> loader, long timestamp) {
            Entry<S, K, V> existing = findEntry(key);
            if (existing != null) {
                if (isExpired(existing, timestamp)) {
                    // Need to clear this entry so that it doesn't prevent storing the future
                    clearExpiredEntry(key, existing, segment);
                } else {
                    return existing;
                }
            }

            final CompletableFuture<Entry<S, K, V>> completableFuture = new CompletableFuture<>();
            CompletableFuture<Entry<S, K, V>> resultFuture;

            final Lock lock = blockLock.writeLock();
            lock.lock();
            try {
                if (inFlight == null) {
                    inFlight = new HashMap<>();
                }
                resultFuture = inFlight.putIfAbsent(key, completableFuture);
            } finally {
                lock.unlock();
            }

            if (resultFuture == null) {
                resultFuture = completableFuture;
                try {
                    V value = loader.load(new Tuple<>(segment.id, key));
                    if (value == null) {
                        final var npe = new NullPointerException("Loader returned null value for key " + key + " in segment " + segment.id);
                        completableFuture.completeExceptionally(npe);
                    } else {
                        completableFuture.complete(new Entry<>(segment.id, key, value, timestamp));
                    }
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e);
                }
            }
            try {
                return resultFuture.get();
            } catch (InterruptedException | ExecutionException e) {
                throw new IllegalStateException(e);
            }
        }

        public boolean remove(Entry<S, K, V> entry) {
            final Lock lock = blockLock.writeLock();
            lock.lock();
            boolean removed = false;
            try {
                if (values != null) {
                    removed = values.remove(entry.key, entry);
                    if (values.isEmpty()) {
                        values = null;
                    }
                }
                if (inFlight != null) {
                    final CompletableFuture<Entry<S, K, V>> future = inFlight.get(entry.key);
                    if (future != null && future.isDone()) {
                        try {
                            final Entry<S, K, V> futureEntry = future.get();
                            if (futureEntry == entry) {
                                removed = inFlight.remove(entry.key, future) || removed;
                                if (inFlight.isEmpty()) {
                                    inFlight = null;
                                }
                            }
                        } catch (ExecutionException | InterruptedException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
            } finally {
                lock.unlock();
            }
            return removed;
        }

        private void clearExpiredEntry(K key, Entry<S, K, V> entry, Segment segment) {
            final Lock lock = blockLock.writeLock();
            lock.lock();
            boolean removed = false;
            try {
                Entry<S, K, V> current = this.values == null ? null : this.values.get(key);
                if (current == null) {
                    final CompletableFuture<Entry<S, K, V>> future = inFlight == null ? null : inFlight.get(key);
                    if (future != null && future.isDone()) {
                        try {
                            current = future.get();
                        } catch (ExecutionException | InterruptedException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
                if (entry == current) {
                    if (this.values != null) {
                        this.values.remove(key);
                    }
                    if (this.inFlight != null) {
                        this.inFlight.remove(key);
                    }
                    removed = true;
                }
            } finally {
                lock.unlock();
            }

            if (removed) {
                removed(entry, segment, RemovalNotification.RemovalReason.EVICTED);
                entries.remove(entry);
            }
        }

        private Entry<S, K, V> findEntry(K key) {
            final Lock lock = blockLock.readLock();
            final CompletableFuture<Entry<S, K, V>> future;
            lock.lock();
            try {
                final Entry<S, K, V> e = values == null ? null : values.get(key);
                if (e != null) {
                    return e;
                }
                future = inFlight == null ? null : inFlight.get(key);
            } finally {
                lock.unlock();
            }
            if (future != null) {
                try {
                    return future.get();
                } catch (ExecutionException e) {
                    assert future.isCompletedExceptionally();
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }
            return null;
        }
    }

}
