/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.util.BitSet;

public class OffsetBitSet extends BitSet {
    private final BitSet other;
    private final int start;
    private final int end;

    private volatile int cardinality = -1;

    public OffsetBitSet(BitSet other, int start, int end) {
        this.other = other;
        this.start = start;
        this.end = end;
    }

    int convertTo(int i) {
        return start + i;
    }

    @Override
    public void set(int i) {
        other.set(convertTo(i));
    }

    @Override
    public boolean getAndSet(int i) {
        return other.getAndSet(convertTo(i));
    }

    @Override
    public void clear(int i) {
        other.clear(convertTo(i));
    }

    @Override
    public void clear(int startIndex, int endIndex) {
        other.clear(convertTo(startIndex), convertTo(endIndex));
    }

    @Override
    public int cardinality() {
        if (cardinality == -1) {
            cardinality = calculateCardinality();
        }
        return cardinality;
    }

    private int calculateCardinality() {
        int c = 0;
        for (int i = start; i < end; i++) {
            var n = other.nextSetBit(i, end-1);
            if (n < end) {
                c++;
                i = n;
            } else {
                break;
            }
        }
        return c;
    }

    @Override
    public int approximateCardinality() {
        return cardinality();
    }

    @Override
    public int prevSetBit(int index) {
        int p = other.prevSetBit(convertTo(index));
        if (p < start) {
            return -1;
        } else {
            return p - start;
        }
    }

    @Override
    public int nextSetBit(int start, int end) {
        int n = other.nextSetBit(convertTo(start), convertTo(end));
        if (n > this.end) {
            return DocIdSetIterator.NO_MORE_DOCS;
        } else {
            return n - this.start;
        }
    }

    @Override
    public long ramBytesUsed() {
        return other.ramBytesUsed();
    }

    @Override
    public boolean get(int index) {
        return other.get(convertTo(index));
    }

    @Override
    public int length() {
        return end - start;
    }
}
