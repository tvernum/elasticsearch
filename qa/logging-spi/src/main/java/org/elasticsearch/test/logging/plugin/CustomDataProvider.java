/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.test.logging.plugin;

import org.elasticsearch.plugins.internal.LoggingDataProvider;

import java.util.Map;
import java.util.Set;

public class CustomDataProvider implements LoggingDataProvider {

    private static final String SAMPLE_KEY = "test.extension";

    @Override
    public Set<String> getDataKeys() {
        return Set.of(SAMPLE_KEY);
    }

    @Override
    public void collectData(Map<String, String> data) {
        data.put(SAMPLE_KEY, "sample-spi-value");
    }
}
