/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.FixedBitSet;
import org.elasticsearch.core.Tuple;

public class RoaringBitSet extends BitSet {

    private final int length;
    private final int cardinality;
    private final long ramBytesUsed;
    private final BitSet[] blocks;

    private static final int ARRAY_SIZE_THRESHOLD = 1 << 12;

    public RoaringBitSet(BitSet clone) {
        this.length = clone.length();
        this.blocks = new BitSet[(length + (1 << 16) - 1) >>> 16];
        int card = 0;
        long ram = 0;
        for (int i = 0; i < blocks.length; i++) {
            final Tuple<BitSet, Integer> tuple = buildBlock(i, clone);
            this.blocks[i] = tuple.v1();
            card += tuple.v2();
            ram += tuple.v1().ramBytesUsed();
        }
        this.cardinality = card;
        this.ramBytesUsed = ram;
    }

    private static Tuple<BitSet, Integer> buildBlock(int blockNumber, BitSet clone) {
        final int start = blockNumber << 16;
        int end = (1 + blockNumber << 16);
        if (end > clone.length()) {
            end = clone.length();
        }

        int blockCardinality = 0;
        for (int i = start; i < end; i++) {
            final int next = clone.nextSetBit(i, end - 1);
            if (next == DocIdSetIterator.NO_MORE_DOCS) {
                break;
            }
            blockCardinality++;
            i = next;
        }

        final OffsetBitSet offsetBitSet = new OffsetBitSet(clone, start, end);
        if (blockCardinality < ARRAY_SIZE_THRESHOLD) {
            return new Tuple<>(new ShortArrayBitSet(offsetBitSet), blockCardinality);
        }
        if ((1 << 16) - blockCardinality < ARRAY_SIZE_THRESHOLD) {
            return new Tuple<>(new ShortArrayBitSet(new InvertedBitSet(offsetBitSet)), blockCardinality);
        }
        return new Tuple<>(FixedBitSet.copyOf(offsetBitSet), blockCardinality);
    }

    private record BlockSplit(int block, int index) {

    }

    private BlockSplit split(int i) {
        final BlockSplit split = new BlockSplit(i >>> 16, i & 0xFFFF);
        if (split.block >= blocks.length) {
            throw new IllegalArgumentException("Index too large [" + split.block + " vs " + blocks.length + "]");
        }
        return split;
    }

    @Override
    public void set(int i) {
        final BlockSplit split = split(i);
        blocks[split.block].set(split.index);
    }

    @Override
    public boolean getAndSet(int i) {
        final BlockSplit split = split(i);
        return blocks[split.block].get(split.index);
    }

    @Override
    public void clear(int i) {
        final BlockSplit split = split(i);
        blocks[split.block].clear(split.index);
    }

    @Override
    public void clear(int startIndex, int endIndex) {
        for (int i = startIndex; i < endIndex; i++) {
            // TODO can do this more efficiently
            clear(i);
        }
    }

    @Override
    public int cardinality() {
        return cardinality;
    }

    @Override
    public int approximateCardinality() {
        return cardinality;
    }

    @Override
    public int prevSetBit(int index) {
        final BlockSplit split = split(index);
        return prevSetBit(split);
    }

    private int prevSetBit(BlockSplit split) {
        final int p = blocks[split.block].prevSetBit(split.index);
        if (p == -1) {
            if (split.block == 0) {
                return -1;
            } else {
                return prevSetBit(new BlockSplit(split.block - 1, 0xFFFF));
            }
        }
        return split.block << 16 + p;
    }

    @Override
    public int nextSetBit(int start, int end) {
        final BlockSplit splitStart = split(start);
        final BlockSplit splitEnd = split(end);
        return nextSetBit(splitStart, splitEnd);
    }

    private int nextSetBit(BlockSplit start, BlockSplit end) {
        if (start.block == end.block) {
            int n = blocks[start.block].nextSetBit(start.index, end.index);
            if (n == DocIdSetIterator.NO_MORE_DOCS) {
                return n;
            } else {
                return start.block << 16 + n;
            }
        } else {
            int n = blocks[start.block].nextSetBit(start.index, 0xFFFF);
            if (n == DocIdSetIterator.NO_MORE_DOCS) {
                return nextSetBit(new BlockSplit(start.block + 1, 0), end);
            } else {
                return start.block << 16 + n;
            }
        }
    }

    @Override
    public long ramBytesUsed() {
        return ramBytesUsed;
    }

    @Override
    public boolean get(int index) {
        final BlockSplit split = split(index);
        return blocks[split.block].get(split.index);
    }

    @Override
    public int length() {
        return length;
    }
}
