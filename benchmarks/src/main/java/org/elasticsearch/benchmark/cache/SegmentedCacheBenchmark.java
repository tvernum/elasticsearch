/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.benchmark.cache;

import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.cache.SegmentedCache;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.core.Tuple;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Group;
import org.openjdk.jmh.annotations.GroupThreads;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

@Fork(1)
@Warmup(time = 20, timeUnit = TimeUnit.SECONDS, iterations = 1)
@Measurement(time = 30, timeUnit = TimeUnit.SECONDS, iterations = 3)
@BenchmarkMode(Mode.Throughput)
public class SegmentedCacheBenchmark {

    public enum Implementation {
        SEGMENTED_CACHE,
        STANDARD_CACHE
    }

    public interface TwoKeyCache<K1, K2, V> {
        void put(K1 k1, K2 k2, V value);

        void computeIfAbsent(K1 k1, K2 k2, Supplier<V> supplier) throws ExecutionException;

        V get(K1 k1, K2 k2);

        void clear();
    }

    public static class SegmentedCacheWrapper implements TwoKeyCache<Integer, String, Boolean> {
        private final SegmentedCache<Integer, String, Boolean> impl;

        public SegmentedCacheWrapper(SegmentedCache<Integer, String, Boolean> impl) {
            this.impl = impl;
        }

        @Override
        public void put(Integer k1, String k2, Boolean value) {
            impl.put(k1, k2, value);
        }

        @Override
        public void computeIfAbsent(Integer k1, String k2, Supplier<Boolean> supplier) {
            impl.computeIfAbsent(k1, k2, ignore -> supplier.get());
        }

        @Override
        public Boolean get(Integer k1, String k2) {
            return impl.get(k1, k2);
        }

        @Override
        public void clear() {
            this.impl.clear();
        }
    }

    public static class StandardCacheWrapper implements TwoKeyCache<Integer, String, Boolean> {
        private final Cache<Tuple<Integer, String>, Boolean> impl;

        public StandardCacheWrapper(Cache<Tuple<Integer, String>, Boolean> impl) {
            this.impl = impl;
        }

        @Override
        public void put(Integer k1, String k2, Boolean value) {
            impl.put(new Tuple<>(k1, k2), value);
        }

        @Override
        public void computeIfAbsent(Integer k1, String k2, Supplier<Boolean> supplier) throws ExecutionException {
            impl.computeIfAbsent(new Tuple<>(k1, k2), ignore -> supplier.get());
        }

        @Override
        public Boolean get(Integer k1, String k2) {
            return impl.get(new Tuple<>(k1, k2));
        }

        @Override
        public void clear() {
            this.impl.invalidateAll();
        }
    }

    @State(Scope.Benchmark)
    public static class GlobalState {
        private TwoKeyCache<Integer, String, Boolean> cache;
        private String[] hotKeys;

        @Param
        public Implementation implementation;

        @Setup(Level.Trial)
        public void initCache() {
            cache = switch (implementation) {
                case SEGMENTED_CACHE -> new SegmentedCacheWrapper(
                    new SegmentedCache<>(null, -1, new SegmentedCache.Expiry(TimeUnit.SECONDS.toNanos(10), -1), null)
                );
                case STANDARD_CACHE -> new StandardCacheWrapper(
                    CacheBuilder.<Tuple<Integer, String>, Boolean>builder().setExpireAfterAccess(TimeValue.timeValueSeconds(10)).build()
                );
            };
            hotKeys = new String[3];

            final ThreadLocalRandom rand = ThreadLocalRandom.current();
            for (int i = 0; i < hotKeys.length; i++) {
                hotKeys[i] = Integer.toHexString(rand.nextInt(0, 1_000));
            }
        }

        @Setup(Level.Iteration)
        public void primeCache() {
            cache.clear();
            for (int i = 0; i < hotKeys.length; i++) {
                cache.put(0, hotKeys[i], true);
            }
        }

    }

    @State(Scope.Thread)
    public static class ThreadState {
        private TwoKeyCache<Integer, String, Boolean> cache;
        private Integer[] segments;
        private String[] warmKeys;

        @Setup
        public void init(GlobalState globalState) {
            final ThreadLocalRandom rand = ThreadLocalRandom.current();
            this.cache = globalState.cache;
            this.segments = new Integer[3];
            for (int i = 0; i < 3; i++) {
                segments[i] = rand.nextInt(1, 5);
            }
            this.warmKeys = new String[5];
            for (int i = 0; i < warmKeys.length; i++) {
                final String key = Integer.toHexString(rand.nextInt(1_000, 1_020));
                for (int s = 0; s < segments.length; s++) {
                    cache.put(segments[s], key, true);
                }
                warmKeys[i] = key;
            }
        }
    }

    @Benchmark
    @Group("multi_threaded")
    @GroupThreads(3)
    public void getHot(GlobalState state) {
        for (String key : state.hotKeys) {
            final Boolean result = state.cache.get(0, key);
            if (result != Boolean.TRUE) {
                throw new IllegalStateException("Cache result for 0:" + key + " was " + result);
            }
        }
    }

    @Benchmark
    @Group("multi_threaded")
    @GroupThreads(1)
    public void putHot(GlobalState state) {
        final String key = state.hotKeys[0];
        state.cache.put(0, key, true);
    }

    @Benchmark
    @Group("multi_threaded")
    @GroupThreads(3)
    public void getWarm(ThreadState state) {
        for (String key : state.warmKeys) {
            for (Integer segment : state.segments) {
                state.cache.get(segment, key);
            }
        }
    }

    @Benchmark
    @Group("multi_threaded")
    @GroupThreads(2)
    public void putWarm(ThreadState state) {
        final Integer segment = random(state.segments);
        final String key = random(state.warmKeys);
        state.cache.put(segment, key, true);
    }

    @Benchmark
    @Group("multi_threaded")
    @GroupThreads(5)
    public void cold(ThreadState state) {
        final Integer segment = random(state.segments);
        final String key = Integer.toHexString(ThreadLocalRandom.current().nextInt(100_000, 1_000_000));
        final Boolean existing = state.cache.get(segment, key);
        if (existing == null) {
            state.cache.put(segment, key, true);
        }
    }

    @Benchmark
    @Group("computation")
    @GroupThreads(3)
    public void getHotComputed(GlobalState state) {
        state.cache.get(0, random(state.hotKeys));
    }

    @Benchmark
    @Group("computation")
    @GroupThreads(1)
    public void computeHot(GlobalState state) throws Exception {
        state.cache.computeIfAbsent(0, random(state.hotKeys), () -> ThreadLocalRandom.current().nextBoolean());
    }

    @Benchmark
    @Group("computation")
    @GroupThreads(3)
    public void getWarmComputed(ThreadState state) {
        state.cache.get(random(state.segments), random(state.warmKeys));
    }

    @Benchmark
    @Group("computation")
    @GroupThreads(2)
    public void computeWarm(ThreadState state) throws Exception {
        state.cache.computeIfAbsent(random(state.segments), random(state.warmKeys), () -> ThreadLocalRandom.current().nextBoolean());
    }

    @Benchmark
    @Group("computation")
    @GroupThreads(5)
    public void computeCold(ThreadState state) throws Exception {
        final Integer segment = random(state.segments);
        final String key = random(state.warmKeys);
        Boolean existing = state.cache.get(segment, key);
        if (existing == null) {
            state.cache.computeIfAbsent(segment, key, () -> false);
        } else if (existing == false) {
            state.cache.put(segment, key, true);
        }
    }

    private <T> T random(T[] array) {
        final ThreadLocalRandom rand = ThreadLocalRandom.current();
        final int index = rand.nextInt(array.length);
        return array[index];
    }

}
