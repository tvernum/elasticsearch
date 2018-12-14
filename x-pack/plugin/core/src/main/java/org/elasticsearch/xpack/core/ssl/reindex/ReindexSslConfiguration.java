/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.ssl.reindex;

import org.apache.http.HttpHost;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.http.client.HttpClientConfigurationCallback;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.ssl.SSLConfiguration;
import org.elasticsearch.xpack.core.ssl.SSLConfigurationSettings;
import org.elasticsearch.xpack.core.ssl.SSLService;

import java.util.List;

/**
 * Configures SSL/TLS for reindex from remote
 */
public class ReindexSslConfiguration implements HttpClientConfigurationCallback {

    public static final String REINDEX_SSL_CONTEXT = "xpack.reindex.ssl";

    private final Logger logger;

    public ReindexSslConfiguration() {
        logger = LogManager.getLogger(getClass());
        logger.debug("Loaded [{}]", getClass());
    }

    @Override
    public void configureHttpClient(String context, HttpHost host, HttpAsyncClientBuilder httpClientBuilder) {
        if ("reindex".equals(context)) {
            final SSLService sslService = XPackPlugin.getSharedSslService();
            if (sslService == null) {
                logger.warn("Cannot configure SSL for reindex because there is no shared SSL service");
                return;
            }
            final SSLConfiguration sslConfiguration = sslService.getSSLConfiguration(REINDEX_SSL_CONTEXT);
            if (sslConfiguration != null) {
                logger.debug("Configuring reindex SSL with [{}]", sslConfiguration);
                httpClientBuilder.setSSLStrategy(sslService.sslIOSessionStrategy(sslConfiguration));
            } else {
                logger.debug("No SSL configuration available for [{}]", REINDEX_SSL_CONTEXT);
            }
        } else {
            logger.trace("Not configuring http client for context [{}]", context);
        }
    }

    public static List<Setting<?>> getSettings() {
        return SSLConfigurationSettings.withPrefix(REINDEX_SSL_CONTEXT + ".").getAllSettings();
    }
}
