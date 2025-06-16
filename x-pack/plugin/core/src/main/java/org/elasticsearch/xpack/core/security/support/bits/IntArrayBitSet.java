/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.RamUsageEstimator;

import java.util.Arrays;

public final class IntArrayBitSet extends BitSet {
    private static final String CLASS_NAME = IntArrayBitSet.class.getSimpleName();
    private final int[] array;
    private final int length;
    private final long ramBytesUsed;

    public IntArrayBitSet(BitSet clone) {
        this.array = new int[clone.cardinality()];
        int start = 0;
        for (int i = 0; i < this.array.length; i++) {
            array[i] = clone.nextSetBit(start);
            start = array[i] + 1;
        }
        this.length = clone.length();
        this.ramBytesUsed = RamUsageEstimator.sizeOf(array);
    }

    @Override
    public void set(int i) {
        notModifiable();
    }

    @Override
    public boolean getAndSet(int i) {
        throw notModifiable();
    }

    @Override
    public void clear(int i) {
        throw notModifiable();
    }

    @Override
    public void clear(int startIndex, int endIndex) {
        notModifiable();
    }

    private static UnsupportedOperationException notModifiable() {
        assert false : CLASS_NAME + " is not modifiable";
        throw new UnsupportedOperationException(CLASS_NAME + " is not modifiable");
    }

    @Override
    public int cardinality() {
        return this.array.length;
    }

    @Override
    public int approximateCardinality() {
        return this.array.length;
    }

    @Override
    public int prevSetBit(int index) {
        int pos = Arrays.binarySearch(this.array, index);
        if (pos >= 0) {
            return index;
        }
        pos = -(pos + 1);
        if (pos == 0) {
            return -1;
        }
        return this.array[pos - 1];
    }

    @Override
    public int nextSetBit(int start, int end) {
        int pos = Arrays.binarySearch(this.array, start);
        final int next;
        if (pos >= 0) {
            next = this.array[pos];
        } else {
            pos = -(pos + 1);
            if (pos >= array.length) {
                return DocIdSetIterator.NO_MORE_DOCS;
            }
            next = this.array[pos];
        }
        if (next >= end) {
            return DocIdSetIterator.NO_MORE_DOCS;
        } else {
            return next;
        }
    }

    @Override
    public long ramBytesUsed() {
        return ramBytesUsed;
    }

    @Override
    public boolean get(int index) {
        return Arrays.binarySearch(this.array, index) >= 0;
    }

    @Override
    public int length() {
        return length;
    }

    @Override
    public String toString() {
        return CLASS_NAME + "{" + "array=" + Arrays.toString(array) + ", length=" + length + ", ramBytesUsed=" + ramBytesUsed + '}';
    }
}
