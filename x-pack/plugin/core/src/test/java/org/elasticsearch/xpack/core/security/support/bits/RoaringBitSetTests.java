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

public class RoaringBitSetTests extends ESTestCase {

    public void testBehaviour() {
        final int length = randomIntBetween(1 << 16, 8 << 16);
        final int size = randomIntBetween(length / 100, length / 10);
        final FixedBitSet original = new FixedBitSet(length);
        for (int i = 0; i < size; i++) {
            original.set(randomValueOtherThanMany(original::get, () -> randomIntBetween(0, length)));
        }
        assertThat(original.cardinality(), equalTo(size));
        assertThat(original.length(), equalTo(length));

        final RoaringBitSet roar = new RoaringBitSet(original);

        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i + " (" + roar + ")", roar.get(i), equalTo(original.get(i)));
        }
        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i + " (" + roar + ")", roar.nextSetBit(i), equalTo(original.nextSetBit(i)));
            final int n = i + randomIntBetween(1, original.length() - i);
            assertThat("At index " + i + " .." + n + " (" + roar + ")", roar.nextSetBit(i, n), equalTo(original.nextSetBit(i, n)));
        }
        for (int i = 0; i < original.length(); i++) {
            assertThat("At index " + i + " (" + roar + ")", roar.prevSetBit(i), equalTo(original.prevSetBit(i)));
        }
    }

}
