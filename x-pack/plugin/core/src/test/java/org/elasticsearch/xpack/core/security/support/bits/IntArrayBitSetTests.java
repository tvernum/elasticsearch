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

public class IntArrayBitSetTests extends ESTestCase {

    public void testBehaviour() {
        final int length = randomIntBetween(500, 2500);
        final int size = randomIntBetween(length / 20, length / 5);
        final FixedBitSet fbs = new FixedBitSet(length);
        for (int i = 0; i < size; i++) {
            fbs.set(randomValueOtherThanMany(fbs::get, () -> randomIntBetween(0, length)));
        }
        assertThat(fbs.cardinality(), equalTo(size));
        assertThat(fbs.length(), equalTo(length));

        final IntArrayBitSet iabs = new IntArrayBitSet(fbs);

        for (int i = 0; i < fbs.length(); i++) {
            assertThat("At index " + i + " (" + iabs + ")", iabs.get(i), equalTo(fbs.get(i)));
        }
        for (int i = 0; i < fbs.length(); i++) {
            assertThat("At index " + i + " (" + iabs + ")", iabs.nextSetBit(i), equalTo(fbs.nextSetBit(i)));
            final int n = i + randomIntBetween(1, fbs.length() - i);
            assertThat("At index " + i + " .." + n + " (" + iabs + ")", iabs.nextSetBit(i, n), equalTo(fbs.nextSetBit(i, n)));
        }
        for (int i = 0; i < fbs.length(); i++) {
            assertThat("At index " + i + " (" + iabs + ")", iabs.prevSetBit(i), equalTo(fbs.prevSetBit(i)));
        }
    }
}
