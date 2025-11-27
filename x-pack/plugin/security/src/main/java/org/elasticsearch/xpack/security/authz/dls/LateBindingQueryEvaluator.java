/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls;

import org.elasticsearch.xpack.core.security.authz.support.DlsQueryEvaluator;
import org.elasticsearch.xpack.security.Security;

public class LateBindingQueryEvaluator implements DlsQueryEvaluator.LateBinding {

    private Security plugin;

    // Needed for SPI
    public LateBindingQueryEvaluator() {}

    // Actually useful for SPI
    public LateBindingQueryEvaluator(Security plugin) {
        this.plugin = plugin;
    }

    @Override
    public DlsQueryEvaluator get() {
        return plugin.getDlsQueryEvaluator();
    }
}
