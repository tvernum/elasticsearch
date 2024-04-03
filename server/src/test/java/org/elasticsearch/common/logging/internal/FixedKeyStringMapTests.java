/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.logging.internal;

import org.elasticsearch.test.ESTestCase;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class FixedKeyStringMapTests extends ESTestCase {

    public void testEmptyKeys() {
        final Map<String, String> map = new FixedKeyStringMap(List.of());
        assertThat(map.isEmpty(), is(true));
        assertThat(map.size(), is(0));
        assertThat(map.containsKey(randomAlphaOfLengthBetween(1, 12)), is(false));
        assertThat(map.containsValue(randomAlphaOfLengthBetween(1, 12)), is(false));
        expectThrows(
            UnsupportedOperationException.class,
            () -> map.put(randomAlphaOfLengthBetween(1, 12), randomAlphaOfLengthBetween(1, 12))
        );
        assertThat(map.remove(randomAlphaOfLengthBetween(1, 12)), nullValue());
        assertThat(map.get(randomAlphaOfLengthBetween(1, 12)), nullValue());
        AtomicBoolean called = new AtomicBoolean(false);
        map.forEach((k, v) -> called.set(true));
        assertThat(called.get(), is(false));
    }

    public void testEmptyValues() {
        final List<String> keys = randomList(3, 20, () -> randomAlphaOfLengthBetween(2, 10));
        final Map<String, String> map = new FixedKeyStringMap(keys);
        assertThat(map.isEmpty(), is(true));
        assertThat(map.size(), is(0));
        final String inKey = randomFrom(keys);
        final String outKey = randomValueOtherThanMany(keys::contains, () -> randomAlphaOfLengthBetween(1, 12));

        assertThat(map.containsKey(inKey), is(false));
        assertThat(map.containsKey(outKey), is(false));
        assertThat(map.containsValue(randomAlphaOfLengthBetween(1, 12)), is(false));
        expectThrows(UnsupportedOperationException.class, () -> map.put(outKey, randomAlphaOfLengthBetween(1, 12)));
        assertThat(map.remove(inKey), nullValue());
        assertThat(map.remove(outKey), nullValue());
        assertThat(map.get(inKey), nullValue());
        assertThat(map.get(outKey), nullValue());

        AtomicBoolean called = new AtomicBoolean(false);
        map.forEach((k, v) -> called.set(true));
        assertThat(called.get(), is(false));
    }

    public void testModification() {
        final List<String> keys = randomList(3, 20, () -> randomAlphaOfLengthBetween(2, 10));
        final Map<String, String> map = new FixedKeyStringMap(keys);

        int size = 0;
        final List<String> subKeys = randomSubsetOf(keys);
        for (String k : subKeys) {
            assertThat(map.size(), is(size));
            assertThat(map.get(k), nullValue());

            final String v = randomAlphaOfLengthBetween(2, 12);
            assertThat(map.put(k, v), nullValue());
            size++;

            assertThat(map.size(), is(size));
            assertThat(map.get(k), is(v));
            assertThat(map.containsKey(k), is(true));
        }
        for (String k : keys) {
            if (subKeys.contains(k)) {
                assertThat(map.containsKey(k), is(true));
                final String v1 = map.get(k);
                assertThat(v1, notNullValue());
                final String v2 = randomAlphaOfLengthBetween(1, 8);
                assertThat(map.put(k, v2), is(v1));
                assertThat(map.get(k), is(v2));
                assertThat(map.containsKey(k), is(true));
            } else {
                assertThat(map.containsKey(k), is(false));
                assertThat(map.get(k), nullValue());
            }
        }

        final String outKey = randomValueOtherThanMany(keys::contains, () -> randomAlphaOfLengthBetween(1, 12));
        assertThat(map.containsKey(outKey), is(false));

        assertThat(map.keySet(), hasSize(size));
        assertThat(map.keySet(), equalTo(Set.copyOf(subKeys)));
        assertThat(map.values(), hasSize(size));

        map.forEach((k, v) -> {
            assertThat(subKeys.contains(k), is(true));
            assertThat(map.get(k), is(v));
        });

        final Set<Map.Entry<String, String>> entries = map.entrySet();
        assertThat(entries, hasSize(size));
        entries.forEach(e -> {
            assertThat(subKeys.contains(e.getKey()), is(true));
            assertThat(map.get(e.getKey()), is(e.getValue()));
        });

        Collections.shuffle(subKeys, random());
        for (String k : subKeys) {
            assertThat(map.size(), is(size));
            assertThat(map.containsKey(k), is(true));
            final String value = map.get(k);
            assertThat(value, notNullValue());

            assertThat(map.remove(k), is(value));
            size--;
            assertThat(map.size(), is(size));
            assertThat(map.containsKey(k), is(false));
        }

        assertThat(map.size(), is(0));
        assertThat(map.isEmpty(), is(true));
    }

}
