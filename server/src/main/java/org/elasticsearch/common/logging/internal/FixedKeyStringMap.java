/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.logging.internal;

import org.apache.logging.log4j.util.BiConsumer;
import org.apache.logging.log4j.util.ReadOnlyStringMap;
import org.apache.logging.log4j.util.StringMap;
import org.apache.logging.log4j.util.TriConsumer;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

public class FixedKeyStringMap implements Map<String, String>, StringMap {

    private final String[] keys;
    private final String[] values;
    private int size;
    private boolean frozen;

    public FixedKeyStringMap(Collection<String> keys) {
        this(sortedArray(keys));
    }

    private static String[] sortedArray(Collection<String> keys) {
        var array = keys.toArray(String[]::new);
        Arrays.sort(array);
        return array;
    }

    private FixedKeyStringMap(String[] keys) {
        this.keys = keys;
        this.values = new String[this.keys.length];
        this.size = 0;
        this.frozen = false;
    }

    public FixedKeyStringMap emptyClone() {
        return new FixedKeyStringMap(this.keys);
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public boolean isEmpty() {
        return size == 0;
    }

    private int indexOfKey(String key) {
        return Arrays.binarySearch(this.keys, key);
    }

    @Override
    public boolean containsKey(Object key) {
        if (key instanceof String k) {
            return containsKey(k);
        } else {
            return false;
        }
    }

    @Override
    public boolean containsValue(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof String v) {
            for (int i = 0; i < values.length; i++) {
                if (v.equals(values[i])) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public String get(Object key) {
        if (key instanceof String k) {
            return get0(k);
        }
        return null;
    }

    private String get0(String k) {
        int idx = indexOfKey(k);
        if (idx >= 0) {
            return values[idx];
        }
        return null;
    }

    private void checkFrozen() {
        if (frozen) {
            throw new UnsupportedOperationException("Map is frozen");
        }
    }

    @Override
    public String put(String key, String value) {
        checkFrozen();
        int idx = indexOfKey(key);
        if (idx >= 0) {
            var old = values[idx];
            values[idx] = value;
            if (old == null) {
                size++;
            }
            return old;
        } else {
            throw new UnsupportedOperationException("Key [" + key + "] is not in the allowed set");
        }
    }

    @Override
    public String remove(Object key) {
        checkFrozen();
        if (key instanceof String k) {
            return this.remove0(k);
        }
        return null;
    }

    private String remove0(String key) {
        int idx = indexOfKey(key);
        if (idx >= 0) {
            var old = values[idx];
            if (old != null) {
                values[idx] = null;
                size--;
            }
            return old;
        }
        return null;
    }

    @Override
    public void putAll(Map<? extends String, ? extends String> m) {
        checkFrozen();
        m.forEach((k, v) -> this.put(k, v));
    }

    @Override
    public void clear() {
        checkFrozen();
        for (int i = 0; i < values.length; i++) {
            values[i] = null;
        }
    }

    @Override
    public Set<String> keySet() {
        // This does not quite fulfil the contract for Map.keySet() because changes in the set are not reflected in the map,
        // but, because the Set is immutable, any such changes will fail
        if (size == keys.length) {
            return Set.of(this.keys);
        } else {
            final String[] populated = new String[size];
            for (int k = 0, p = 0; k < keys.length; k++) {
                if (values[k] != null) {
                    populated[p] = keys[k];
                    p++;
                }
            }
            return Set.of(populated);
        }
    }

    @Override
    public Collection<String> values() {
        // This does not quite fulfil the contract for Map.values() because changes in the collection are not reflected in the map,
        // but, because the Collection is immutable, any such changes will fail
        if (size == values.length) {
            return List.of(values);
        } else {
            return Stream.of(values).filter(Objects::nonNull).toList();
        }
    }

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Set<Entry<String, String>> entrySet() {
        Entry<String, String>[] entries = new Entry[size];
        for (int k = 0, e = 0; k < keys.length; k++) {
            if (values[k] != null) {
                entries[e] = Map.entry(keys[k], values[k]);
                e++;
            }
        }
        return Set.of(entries);
    }

    @Override
    public void freeze() {
        this.frozen = true;
    }

    @Override
    public boolean isFrozen() {
        return frozen;
    }

    @Override
    public void putAll(ReadOnlyStringMap source) {
        checkFrozen();
        source.<String>forEach((k, v) -> this.put(k, v));
    }

    @Override
    public void putValue(String key, Object value) {
        if (value instanceof String v) {
            this.put(key, v);
        }
    }

    @Override
    public void remove(String key) {
        this.remove0(key);
    }

    @Override
    public Map<String, String> toMap() {
        return this;
    }

    @Override
    public boolean containsKey(String key) {
        int idx = indexOfKey(key);
        return idx >= 0 && values[idx] != null;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> void forEach(BiConsumer<String, ? super V> action) {
        for (int i = 0; i < keys.length; i++) {
            String v = values[i];
            if (v != null) {
                action.accept(keys[i], (V) v);
            }
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V, S> void forEach(TriConsumer<String, ? super V, S> action, S state) {
        for (int i = 0; i < keys.length; i++) {
            String v = values[i];
            if (v != null) {
                action.accept(keys[i], (V) v, state);
            }
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> V getValue(String key) {
        return (V) get0(key);
    }
}
