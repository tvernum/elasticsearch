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

public class InvertedBitSetTests extends ESTestCase {

    public void testBehaviour() {
        final int length = randomIntBetween(500, 2500);
        final int size = randomIntBetween(length / 20, length * 2 / 3);
        final FixedBitSet originalFixed = new FixedBitSet(length);
        for (int i = 0; i < size; i++) {
            originalFixed.set(randomValueOtherThanMany(originalFixed::get, () -> randomIntBetween(0, length)));
        }
        assertThat(originalFixed.cardinality(), equalTo(size));
        assertThat(originalFixed.length(), equalTo(length));

        final FixedBitSet invertedFixed = new FixedBitSet(length);
        for (int i = 0; i < originalFixed.length(); i++) {
            if (originalFixed.get(i) == false) {
                invertedFixed.set(i);
            }
        }

        final InvertedBitSet inv = new InvertedBitSet(originalFixed);
        for (int i = 0; i < originalFixed.length(); i++) {
            assertThat("At index " + i + " (" + inv + ")", inv.get(i), equalTo(invertedFixed.get(i)));
        }
        for (int i = 0; i < originalFixed.length(); i++) {
            assertThat("At index " + i + " (" + inv + ")", inv.nextSetBit(i), equalTo(invertedFixed.nextSetBit(i)));
            final int n = i + randomIntBetween(1, invertedFixed.length() - i);
            assertThat("At index " + i + " .." + n + " (" + inv + ")", inv.nextSetBit(i, n), equalTo(invertedFixed.nextSetBit(i, n)));
        }
        for (int i = 0; i < originalFixed.length(); i++) {
            assertThat("At index " + i + " (" + inv + ")", inv.prevSetBit(i), equalTo(invertedFixed.prevSetBit(i)));
        }

        assertThat(inv.cardinality(), equalTo(invertedFixed.cardinality()));
    }

}
