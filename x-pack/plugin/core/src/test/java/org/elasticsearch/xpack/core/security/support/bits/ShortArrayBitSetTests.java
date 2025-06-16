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

public class ShortArrayBitSetTests extends ESTestCase {

    public void testBehaviour() {
        final int length = randomIntBetween(50, Short.MAX_VALUE - 1);
        final int size = randomIntBetween(length / 20, length / 5);
        final FixedBitSet fixed = new FixedBitSet(length);
        for (int i = 0; i < size; i++) {
            fixed.set(randomValueOtherThanMany(fixed::get, () -> randomIntBetween(0, length)));
        }
        assertThat(fixed.cardinality(), equalTo(size));
        assertThat(fixed.length(), equalTo(length));

        final ShortArrayBitSet array = new ShortArrayBitSet(fixed);

        for (int i = 0; i < fixed.length(); i++) {
            assertThat("At index " + i + " (" + array + ")", array.get(i), equalTo(fixed.get(i)));
        }
        for (int i = 0; i < fixed.length(); i++) {
            assertThat("At index " + i + " (" + array + ")", array.nextSetBit(i), equalTo(fixed.nextSetBit(i)));
            final int n = i + randomIntBetween(1, fixed.length() - i);
            assertThat("At index " + i + " .." + n + " (" + array + ")", array.nextSetBit(i, n), equalTo(fixed.nextSetBit(i, n)));
        }
        for (int i = 0; i < fixed.length(); i++) {
            assertThat("At index " + i + " (" + array + ")", array.prevSetBit(i), equalTo(fixed.prevSetBit(i)));
        }
    }
}
