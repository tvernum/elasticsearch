/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.common.cache;

import org.elasticsearch.common.util.concurrent.CountDown;
import org.elasticsearch.test.ESTestCase;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class SegmentedCacheTests extends ESTestCase {

    public void testBasicPutAndGet() {
        final SegmentedCache<Long, String, String> cache = new SegmentedCache<>((k, v) -> v.length(), -1, null, null);
        cache.put(1L, "a", "A");
        cache.put(1L, "b", "B");
        cache.put(2L, "a", "AA");
        cache.put(2L, "c", "CC");

        assertThat(cache.get(1L, "a"), is("A"));
        assertThat(cache.get(2L, "a"), is("AA"));
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "b"), nullValue());
        assertThat(cache.get(1L, "c"), nullValue());
        assertThat(cache.get(2L, "c"), is("CC"));
        assertThat(cache.count(), equalTo(4));
        assertThat(cache.weight(), equalTo(1L + 2L + 1L + 2L));

        cache.put(1L, "a", "_A");
        cache.put(2L, "a", "A_");
        cache.put(3L, "a", "_A_");

        assertThat(cache.get(1L, "a"), is("_A"));
        assertThat(cache.get(2L, "a"), is("A_"));
        assertThat(cache.get(3L, "a"), is("_A_"));
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "b"), nullValue());
        assertThat(cache.get(1L, "c"), nullValue());
        assertThat(cache.get(2L, "c"), is("CC"));
        assertThat(cache.count(), equalTo(5));
        assertThat(cache.weight(), equalTo(2L + 2L + 3L + 1L + 2L));
    }

    public void testWriteExpiry() {
        AtomicLong clock = new AtomicLong(0);
        final SegmentedCache<Long, String, Object> cache = new SegmentedCache<>(
            null,
            -1,
            new SegmentedCache.Expiry(-1, 100),
            null,
            clock::get
        );
        cache.put(1L, "a", "A");
        clock.addAndGet(10);
        cache.put(1L, "b", "B");
        cache.put(2L, "a", "AA");

        assertThat(cache.get(1L, "a"), is("A"));
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "a"), is("AA"));
        assertThat(cache.count(), equalTo(3));

        clock.addAndGet(50);

        assertThat(cache.get(1L, "a"), is("A"));
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "a"), is("AA"));
        assertThat(cache.count(), equalTo(3));

        clock.addAndGet(35);

        assertThat(cache.get(1L, "a"), is("A"));
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "a"), is("AA"));
        assertThat(cache.count(), equalTo(3));

        clock.addAndGet(10);

        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("B"));
        assertThat(cache.get(2L, "a"), is("AA"));
        assertThat(cache.count(), equalTo(2));

        clock.addAndGet(10);

        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), nullValue());
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.count(), equalTo(0));
    }

    public void testAccessExpiry() {
        AtomicLong clock = new AtomicLong(0);
        final SegmentedCache<Long, String, Object> cache = new SegmentedCache<>(
            null,
            -1,
            new SegmentedCache.Expiry(100, -1),
            null,
            clock::get
        );

        for (int k = 0; k < 64; k++) {
            for (long s = 1; s <= 5; s++) {
                cache.put(s, Integer.toHexString(k), s + k);
            }
        }

        // Repeatedly get entries.
        // Although time is incrementing, each entry is retrieved every 64 nanos, so they never exceed the 100ns access expiry
        for (int i = 0; i < 100; i++) {
            for (int k = 0; k < 64; k++) {
                for (long s = 1; s <= 5; s++) {
                    assertThat(cache.get(s, Integer.toHexString(k)), equalTo(s + k));
                }
                clock.incrementAndGet();
            }
        }

        // Move time forward. (64 + 30) is less than 100ns so all entries are still active.
        clock.addAndGet(30);

        // Repeatedly get the even entries for segments 1 and 5
        for (int i = 0; i < 100; i++) {
            for (int k = 0; k < 64; k += 2) {
                assertThat(cache.get(1L, Integer.toHexString(k)), equalTo(k + 1L));
                assertThat(cache.get(5L, Integer.toHexString(k)), equalTo(k + 5L));
            }
        }

        // Move time forward again.
        // The items that were retrieved in the last loop are still active (90ns is less than 100ns).
        // The items that were not retrieved are now expired (30 + 90) is granter than 100ns
        clock.addAndGet(90);

        // Check that the even items in segments 1 and 5 are still active, but all other entries are expired
        for (int i = 0; i < 100; i++) {
            for (int k = 0; k < 64; k++) {
                for (long s = 1; s <= 5; s++) {
                    final Object got = cache.get(s, Integer.toHexString(k));
                    if (k % 2 == 0 && (s == 1 || s == 5)) {
                        assertThat(got, equalTo(s + k));
                    } else {
                        assertThat(got, nullValue());
                    }
                }
            }
        }
    }

    public void testMultiThreadedGetAndPut() throws Exception {
        final int nThreads = 5;
        final AtomicLong clock = new AtomicLong(0);
        final int writeExpiry = nThreads * 5 + 10;
        final SegmentedCache<Long, String, Object> cache = new SegmentedCache<>(
            null,
            -1,
            new SegmentedCache.Expiry(-1, writeExpiry),
            null,
            clock::get
        );

        try (ExecutorService executor = Executors.newFixedThreadPool(nThreads);) {
            final CountDown countDown = new CountDown(nThreads);
            for (int i = 0; i < nThreads; i++) {
                executor.submit(() -> {
                    final Thread thread = Thread.currentThread();
                    try {
                        cache.put(0L, "a", "A");
                        cache.put(0L, "*", thread.getName());
                        cache.put(0L, thread.getName(), thread.threadId());
                        cache.put(thread.threadId(), "a", "AAA");

                        clock.addAndGet(5);

                        assertThat(cache.get(0L, thread.getName()), is(thread.threadId()));
                        assertThat(cache.get(thread.threadId(), "a"), is("AAA"));

                        countDown.countDown();
                    } catch (Throwable e) {
                        logger.warn(() -> thread.getName() + " : ERROR", e);
                    }
                });
            }

            assertBusy(() -> assertTrue(countDown.isCountedDown()), 250, TimeUnit.MILLISECONDS);

            assertThat(cache.get(0L, "a"), is("A"));
            assertThat(cache.get(0L, "*"), notNullValue());
            assertThat(cache.count(), equalTo(2 + nThreads * 2));

            clock.addAndGet(writeExpiry - 1);

            assertThat(cache.get(0L, "a"), nullValue());
            assertThat(cache.get(0L, "*"), nullValue());
        }
    }

    public void testWeightEviction() {
        AtomicLong clock = new AtomicLong(0);
        final SegmentedCache<Long, String, String> cache = new SegmentedCache<>((k, v) -> v.length(), 10, null, null, clock::get);

        cache.put(1L, "a", "1a");
        assertThat(cache.count(), equalTo(1));
        assertThat(cache.weight(), equalTo(2L));

        cache.put(1L, "b", "1b");
        assertThat(cache.count(), equalTo(2));
        assertThat(cache.weight(), equalTo(4L));

        cache.put(2L, "a", "2a");
        assertThat(cache.count(), equalTo(3));
        assertThat(cache.weight(), equalTo(6L));

        cache.put(2L, "b", "2b");
        assertThat(cache.count(), equalTo(4));
        assertThat(cache.weight(), equalTo(8L));

        cache.put(3L, "a", "3a");
        assertThat(cache.count(), equalTo(5));
        assertThat(cache.weight(), equalTo(10L));

        assertThat(cache.get(1L, "a"), is("1a"));
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(2L, "a"), is("2a"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(3L, "a"), is("3a"));
        assertThat(cache.get(3L, "b"), nullValue());

        cache.put(3L, "b", "3b");
        assertThat(cache.count(), equalTo(5));
        assertThat(cache.weight(), equalTo(10L));
        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(2L, "a"), is("2a"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(3L, "a"), is("3a"));
        assertThat(cache.get(3L, "b"), is("3b"));

        // If we access 1b, then it is no longer LRU, and 2a should be evicted
        assertThat(cache.get(1L, "b"), is("1b"));
        cache.put(4L, "_", "4");
        assertThat(cache.count(), equalTo(5));
        assertThat(cache.weight(), equalTo(9L));
        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(3L, "a"), is("3a"));
        assertThat(cache.get(3L, "b"), is("3b"));
        assertThat(cache.get(4L, "_"), is("4"));

        cache.put(4L, "*", "4");
        assertThat(cache.count(), equalTo(6));
        assertThat(cache.weight(), equalTo(10L));
        assertThat(cache.get(4L, "_"), is("4"));
        assertThat(cache.get(4L, "*"), is("4"));
        assertThat(cache.get(3L, "a"), is("3a"));
        assertThat(cache.get(3L, "b"), is("3b"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(1L, "a"), nullValue());

        cache.put(1L, "_", "1");
        assertThat(cache.count(), equalTo(6));
        assertThat(cache.weight(), equalTo(10L));
        assertThat(cache.get(3L, "a"), is("3a"));
        assertThat(cache.get(3L, "b"), is("3b"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "_"), is("1"));
        assertThat(cache.get(4L, "_"), nullValue());
        assertThat(cache.get(4L, "*"), is("4"));

        cache.put(2L, "_", "2");
        assertThat(cache.count(), equalTo(6));
        assertThat(cache.weight(), equalTo(9L));
        assertThat(cache.get(3L, "a"), nullValue());
        assertThat(cache.get(3L, "b"), is("3b"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "_"), is("1"));
        assertThat(cache.get(4L, "_"), nullValue());
        assertThat(cache.get(4L, "*"), is("4"));

        cache.put(3L, "_", "2");
        assertThat(cache.count(), equalTo(7));
        assertThat(cache.weight(), equalTo(10L));
        assertThat(cache.get(3L, "a"), nullValue());
        assertThat(cache.get(3L, "b"), is("3b"));
        assertThat(cache.get(2L, "b"), is("2b"));
        assertThat(cache.get(2L, "a"), nullValue());
        assertThat(cache.get(1L, "b"), is("1b"));
        assertThat(cache.get(1L, "a"), nullValue());
        assertThat(cache.get(1L, "_"), is("1"));
        assertThat(cache.get(4L, "_"), nullValue());
        assertThat(cache.get(4L, "*"), is("4"));
    }

    public void testCacheLoader() throws Exception {
        final AtomicLong clock = new AtomicLong(0);
        final SegmentedCache<Long, String, Object> cache = new SegmentedCache<>(
            null,
            -1,
            new SegmentedCache.Expiry(-1, 100),
            null,
            clock::get
        );

        final int nThreads = 5;
        final Object[] computations = new Object[nThreads];
        final AtomicInteger computationCount = new AtomicInteger(0);
        final Thread[] threads = new Thread[nThreads];
        final CountDown countDown = new CountDown(nThreads);
        for (int i = 0; i < threads.length; i++) {
            final int n = i;
            threads[i] = new Thread(() -> {
                clock.incrementAndGet();
                cache.put(0L, "*", "shared-before");
                cache.put(0L, "#" + n, n);
                final Object computed = cache.computeIfAbsent(0L, "computed", segKey -> {
                    computationCount.incrementAndGet();
                    return "thread:" + n;
                });
                computations[n] = computed;
                cache.put(0L, "*", "shared-after");
                countDown.countDown();
            }, "cache-loader-" + n);
        }
        for (int i = 0; i < threads.length; i++) {
            threads[i].start();
            clock.incrementAndGet();
        }

        assertBusy(() -> assertTrue(countDown.isCountedDown()), 1, TimeUnit.SECONDS);
        assertThat(computationCount.get(), is(1));
        for (int i = 1; i < threads.length; i++) {
            assertThat(computations[i], sameInstance(computations[0]));
        }

        clock.incrementAndGet();
        assertThat(cache.get(0L, "computed"), sameInstance(computations[0]));
        assertThat(cache.get(0L, "*"), equalTo("shared-after"));
        for (int i = 0; i < threads.length; i++) {
            assertThat(cache.get(0L, "#" + i), equalTo(i));
        }
    }

}
