/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.support.bits;

import org.apache.lucene.util.FixedBitSet;
import org.elasticsearch.test.ESTestCase;

import static org.hamcrest.Matchers.equalTo;

public class OffsetBitSetTests extends ESTestCase {

    public void testBehaviourOffsetZero() {
        final FixedBitSet original = randomFixedBitSet();

        final OffsetBitSet offset = new OffsetBitSet(original, 0, original.length());
        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i, offset.get(i), equalTo(original.get(i)));
        }
        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i, offset.nextSetBit(i), equalTo(original.nextSetBit(i)));
            final int n = i + randomIntBetween(1, offset.length() - i);
            assertThat("At index " + i + " .." + n, offset.nextSetBit(i, n), equalTo(original.nextSetBit(i, n)));
        }
        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i, offset.prevSetBit(i), equalTo(original.prevSetBit(i)));
        }

        assertThat(offset.cardinality(), equalTo(original.cardinality()));
    }

    public void testBehaviourOffsetOne() {
        final FixedBitSet original = randomFixedBitSet();

        final OffsetBitSet offset = new OffsetBitSet(original, 1, original.length());
        for (int i = 1; i < original.length(); i++) {
            assertThat("At index " + i, offset.get(i - 1), equalTo(original.get(i)));
        }
        for (int i = 1; i < original.length(); i++) {
            assertThat("At index " + i, offset.nextSetBit(i - 1), equalTo(original.nextSetBit(i) - 1));
        }
        for (int i = original.nextSetBit(1); i < original.length(); i++) {
            assertThat("At index " + i, offset.prevSetBit(i - 1), equalTo(original.prevSetBit(i) - 1));
        }

        assertThat(offset.cardinality(), equalTo(original.cardinality() - (original.get(0) ? 1 : 0)));
    }

    private static FixedBitSet randomFixedBitSet() {
        final int length = randomIntBetween(500, 2500);
        final int size = randomIntBetween(length / 20, length * 2 / 3);
        final FixedBitSet original = new FixedBitSet(length);
        for (int i = 0; i < size; i++) {
            original.set(randomValueOtherThanMany(original::get, () -> randomIntBetween(0, length - 1)));
        }
        assertThat(original.cardinality(), equalTo(size));
        assertThat(original.length(), equalTo(length));
        return original;
    }
}
