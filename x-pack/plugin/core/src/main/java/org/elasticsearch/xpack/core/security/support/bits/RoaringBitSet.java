/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.util.BitSet;
import org.roaringbitmap.RoaringBitmap;

/**
 * Adapter for {@link RoaringBitmap} into a lucene {@link BitSet}.
 * Lucene has its own Roaring implementation for {@link org.apache.lucene.util.RoaringDocIdSet}, but not one for BitSets
 */
public class RoaringBitSet extends BitSet {

    private final RoaringBitmap roar;

    public RoaringBitSet(BitSet other) {
        this.roar = new RoaringBitmap();
        for (int i = 0; i < other.length(); i++) {
            final int next = other.nextSetBit(i);
            if (next == DocIdSetIterator.NO_MORE_DOCS) {
                break;
            }
            roar.add(next);
            i = next;
        }
    }

    @Override
    public int length() {
        if (roar.isEmpty()) {
            return 0;
        }
        return roar.last() + 1;
    }

    @Override
    public int cardinality() {
        return roar.getCardinality();
    }

    @Override
    public int approximateCardinality() {
        return cardinality();
    }

    @Override
    public long ramBytesUsed() {
        return roar.getLongSizeInBytes();
    }

    @Override
    public boolean get(int index) {
        return roar.contains(index);
    }

    @Override
    public void set(int i) {
        this.roar.add(i);
    }

    @Override
    public boolean getAndSet(int i) {
        var b = roar.contains(i);
        if (b == false) {
            roar.add(i);
        }
        return b;
    }

    @Override
    public void clear(int i) {
        this.roar.remove(i);
    }

    @Override
    public void clear(int startIndex, int endIndex) {
        this.roar.remove(startIndex, (long) endIndex);
    }

    @Override
    public int prevSetBit(int index) {
        return (int) roar.previousValue(index);
    }

    @Override
    public int nextSetBit(int start, int end) {
        long next = roar.nextValue(start);
        if (next >= end || next == -1) {
            return DocIdSetIterator.NO_MORE_DOCS;
        }
        return (int) next;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{length=" + length() + ",cardinality=" + cardinality() + ",ram= " + ramBytesUsed() + '}';
    }
}
