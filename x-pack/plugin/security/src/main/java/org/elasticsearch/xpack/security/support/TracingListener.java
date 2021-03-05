/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.support;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;

public class TracingListener<T> extends ActionListener.Delegating<T, T> {
    private final String context;
    private final Logger logger;

    public TracingListener(ActionListener<T> delegate, String context, Logger logger) {
        super(delegate);
        this.context = context;
        this.logger = logger;
    }

    @Override
    public void onResponse(T response) {
        logger.trace("{} success: {}", context, response);
        delegate.onResponse(response);
    }

    @Override
    public void onFailure(Exception e) {
        logger.debug("{} failed: {}", context, e.toString());
        super.onFailure(e);
    }
}
