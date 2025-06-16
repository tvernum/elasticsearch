/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.util.BitSet;

public class InvertedBitSet extends BitSet {

    private final BitSet other;

    public InvertedBitSet(BitSet other) {
        this.other = other;
    }

    @Override
    public void set(int i) {
        other.clear(i);
    }

    @Override
    public boolean getAndSet(int i) {
        final boolean b = get(i);
        set(i);
        return b;
    }

    @Override
    public void clear(int i) {
        other.set(i);
    }

    @Override
    public void clear(int startIndex, int endIndex) {
        for (int i = startIndex; i < endIndex; i++) {
            this.clear(i);
        }
    }

    @Override
    public int cardinality() {
        return other.length() - other.cardinality();
    }

    @Override
    public int approximateCardinality() {
        return other.length() - other.approximateCardinality();
    }

    @Override
    public int prevSetBit(int index) {
        for (int i = index; i >= 0; i--) {
            if (this.get(i)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public int nextSetBit(int start, int end) {
        for (int i = start; i < end; i++) {
            if (this.get(i)) {
                return i;
            }
        }
        return DocIdSetIterator.NO_MORE_DOCS;
    }

    @Override
    public long ramBytesUsed() {
        return other.ramBytesUsed();
    }

    @Override
    public boolean get(int index) {
        return other.get(index) == false;
    }

    @Override
    public int length() {
        return other.length();
    }
}
